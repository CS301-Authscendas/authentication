import {
    BadRequestException,
    CACHE_MANAGER,
    HttpException,
    Inject,
    Injectable,
    InternalServerErrorException,
    UnauthorizedException,
} from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { TwoFATokenObj, UserDTO, UserStatus } from "../dto/user.dto";
import { NotificationService } from "../notification/notification.service";
import { UserService } from "../user/user.service";

import { HttpService } from "@nestjs/axios";
import * as bcrypt from "bcryptjs";
import { Cache } from "cache-manager";
import { decode, JwtPayload, verify } from "jsonwebtoken";
import { JwksClient, SigningKey } from "jwks-rsa";
import { BankSSOUser } from "../dto/bank-sso-user.dto";
import { LoginMethodEnum } from "../dto/login-method.enum";
import { Organization } from "../dto/organization.dto";
import { UserCreationDTO } from "../dto/user-creation.dto";
import { UserJSONPayload } from "../dto/user-json-payload.dto";
import { KmsService } from "../kms/kms.service";
import { OrganizationService } from "../organization/organization.service";
import { UtilHelper } from "../utils";
import { Auth0LoginDataDTO } from "src/dto/auth0-login-data.dto";
import { stringify } from "qs";

@Injectable()
export class AuthService {
    private twoFaTokenWindow: number;
    private ssoPublicKey: string;
    private jwksClient: JwksClient;

    constructor(
        private readonly httpService: HttpService,
        private readonly userService: UserService,
        private readonly notificationService: NotificationService,
        private readonly organizationService: OrganizationService,
        private readonly configService: ConfigService,
        private readonly kmsService: KmsService,
        @Inject(CACHE_MANAGER) private readonly orgCacheManager: Cache,
        @Inject(CACHE_MANAGER) private readonly userCacheManager: Cache,
    ) {
        const tokenWindow = configService.get("2FA_TOKEN_WINDOW_SECONDS");
        this.ssoPublicKey = this.configService.get("SSO_PUBLIC_KEY") ?? "";

        if (UtilHelper.isProduction() && this.ssoPublicKey === "") {
            throw new InternalServerErrorException("Missing environment variable for sso token");
        }

        if (!tokenWindow && UtilHelper.isProduction()) {
            throw new InternalServerErrorException("2FA_TOKEN_WINDOW_SECONDS has not been set!");
        }

        this.twoFaTokenWindow = parseInt(tokenWindow);

        this.jwksClient = new JwksClient({
            jwksUri: this.configService.get("JWKS_URI") ?? "",
            rateLimit: true,
            cache: true,
            cacheMaxEntries: 10,
            cacheMaxAge: 5,
            jwksRequestsPerMinute: 10,
        });
    }

    // Function to hash plain text password using bcrypt.
    async hashPassword(password: string): Promise<string> {
        const salt = await bcrypt.genSalt(10);
        return await bcrypt.hash(password, salt);
    }

    // Function to compare plain text password and hashed password using bcrypt.
    private async comparePassword(hashedPassword: string, unhashedPassword: string): Promise<boolean> {
        return await bcrypt.compare(unhashedPassword, hashedPassword);
    }

    // Function to generate JWT Token, encoding a JSON payload.
    async generateJWTToken(payload: UserJSONPayload): Promise<string> {
        return await this.kmsService.sign(payload);
    }

    async refreshJWTToken(token: string): Promise<string> {
        const jwtToken: string = token.replace("Bearer", "").trim();
        const userPayload = await this.kmsService.decode(jwtToken);

        const email = userPayload.email;
        if (!email) {
            throw new BadRequestException("Invalid JWT token!");
        }
        return await this.kmsService.sign(userPayload);
    }

    validateSsoToken(jwtToken: string, key: string): boolean {
        try {
            verify(jwtToken, key, { algorithms: ["RS256"] });
            return true;
        } catch (error) {
            throw new BadRequestException(error.message ?? "Invalid SSO jwt token");
        }
    }

    async getJwksPublicKey(keyId: string): Promise<string> {
        const matchingkey: SigningKey = await this.jwksClient.getSigningKey(keyId);
        return matchingkey.getPublicKey();
    }

    async validateJwksToken(jwtToken: string): Promise<string> {
        try {
            const result = decode(jwtToken, { complete: true });
            if (!result) {
                throw new BadRequestException("Invalid jwt token!");
            }

            const { header } = result;
            const { kid } = header;

            const publicKey = await this.getJwksPublicKey(kid ?? "");
            const jwtPayload = verify(jwtToken, publicKey);

            return (jwtPayload as JwtPayload)?.email;
        } catch (error) {
            throw new BadRequestException(error.message ?? "Unable to validate Auth0 jwt token");
        }
    }

    async checkJWTValidity(token: string, loginMethod: LoginMethodEnum): Promise<UserDTO> {
        const jwtToken: string = token.replace("Bearer", "").trim();
        let dbUser: UserDTO | undefined;
        let email = "";

        switch (loginMethod) {
            case LoginMethodEnum.Hosted: {
                const hostedTokenData = await this.kmsService.decode(jwtToken);
                email = hostedTokenData.email;
                break;
            }
            case LoginMethodEnum.SSO: {
                this.validateSsoToken(jwtToken, this.ssoPublicKey);
                const ssoUser: BankSSOUser = await this.userService.fetchUserDetailsSSO(jwtToken);
                email = ssoUser.email;
                break;
            }
            case LoginMethodEnum.Auth0: {
                email = await this.validateJwksToken(jwtToken);
                break;
            }
            default:
                break;
        }

        dbUser = await this.userCacheManager.get(email);
        if (!dbUser) {
            dbUser = await this.userService.fetchUserDetails(email);
            await this.userCacheManager.set(email, dbUser);
        }

        if (!dbUser) {
            throw new UnauthorizedException("Invalid JWT token.");
        }

        return dbUser;
    }

    async triggerSendLoginAlertEmail(email: string): Promise<void> {
        let userDetails: UserDTO | undefined = await this.userCacheManager.get(email);

        if (!userDetails) {
            userDetails = await this.userService.fetchUserDetails(email);
            this.userCacheManager.set(email, userDetails);
        }

        const name = `${userDetails.firstName} ${userDetails.lastName}`;
        this.notificationService.triggerLoginAlertEmail(name, email);
    }

    // Function to request new JWT Token from Bank SSO.
    async ssoTokenRequest(authCode: string, callbackUri: string): Promise<string> {
        const baseUrl = this.configService.get("SSO_BASE_URL");
        const clientId = this.configService.get("SSO_CLIENT_ID");
        const clientSecret = this.configService.get("SSO_CLIENT_SECRET");

        const requestUrl = `${baseUrl}/oauth/token`;

        const requestBody = {
            client_id: clientId,
            client_secret: clientSecret,
            redirect_uri: callbackUri,
            grant_type: "authorization_code",
            code: authCode,
        };

        try {
            const res = await this.httpService.axiosRef.post(requestUrl, requestBody);
            return res?.data?.access_token;
        } catch (error) {
            if (error.code === "ECONNREFUSED") {
                throw new InternalServerErrorException("Organization microservice error.");
            }
            throw new HttpException(error?.response?.data, error?.response?.status);
        }
    }

    // Function to save new user information and update status to 'APPROVED'.
    async signup(userCreationObj: UserCreationDTO): Promise<boolean> {
        const email = userCreationObj.email;

        let userDetails: UserDTO = await this.userService.fetchUserDetails(email);

        if (userDetails.status === UserStatus.Approved) {
            throw new BadRequestException("User has already signed up!");
        }

        // Hash the plain text password
        userDetails.password = await this.hashPassword(userCreationObj.password);

        // Update particulars
        const { firstName, lastName, phoneNumber, birthDate } = userCreationObj;
        userDetails = this.updateUserCreationObj(userDetails, firstName, lastName, phoneNumber, birthDate);

        // Save particulars
        const success = await this.userService.updateUserDetails(userDetails);

        const name = `${userDetails.firstName} ${userDetails.lastName}`;

        this.notificationService.triggerRegistrationSuccessEmail(name, email);

        return success;
    }

    async validateUserCredentials(email: string, password: string): Promise<UserDTO> {
        const userDetails: UserDTO = await this.userService.fetchFullUserDetails(email);

        if (userDetails.status !== UserStatus.Approved) {
            throw new UnauthorizedException("User has not signed up!");
        }

        const hashedPassword: string = userDetails.password;
        const success = await this.comparePassword(hashedPassword, password);

        if (!success) {
            throw new UnauthorizedException("Invalid password");
        }

        return userDetails;
    }

    // Function to validate user credentials and request for a new 2FA token for user.
    async hostedLogin(email: string, password: string): Promise<boolean> {
        const userDetails: UserDTO = await this.validateUserCredentials(email, password);
        await this.generate2FAToken(userDetails.email);
        return true;
    }

    getCurrentSecondsFromEpoch(): number {
        const now = new Date();
        return Math.round(now.getTime() / 1000);
    }

    // Function to validate user credentials and request for a new 2FA token for user.
    async generate2FAToken(email: string): Promise<void> {
        const userDetails: UserDTO = await this.userService.fetchUserDetails(email);
        const token: string = Math.floor(100000 + Math.random() * 900000).toString();

        const twoFaObj: TwoFATokenObj = {
            token: token,
            creationDate: this.getCurrentSecondsFromEpoch(),
        };

        // Save 2FA secret via Organizations microservice.
        this.userService.saveTwoFactorSecret(email, twoFaObj);

        const name = `${userDetails.firstName} ${userDetails.lastName}`;
        // Send 2FA token via Notifications microservice.
        this.notificationService.trigger2FATokenEmail(name, email, token);
    }

    // Function to validate input 2FA token using secret generated for user and return a new JWT token.
    async validate2FAToken(email: string, userToken: string): Promise<boolean> {
        const userDetails: UserDTO = await this.userService.fetchFullUserDetails(email);
        const tokenObj: TwoFATokenObj | null = userDetails.twoFATokenObj;

        if (!tokenObj) {
            throw new InternalServerErrorException(`${email} does not have a 2FA secret.`);
        }

        const { token, creationDate } = tokenObj;
        if (token === userToken && creationDate + this.twoFaTokenWindow >= this.getCurrentSecondsFromEpoch()) {
            this.userService.clearTwoFactorSecret(email);
            return true;
        }

        return false;
    }

    // Function to update user object.
    updateUserCreationObj(
        userDetails: UserDTO,
        firstName: string,
        lastName: string,
        phoneNumber: string,
        birthDate: string,
        status = UserStatus.Approved,
    ): UserDTO {
        userDetails.firstName = firstName;
        userDetails.lastName = lastName;
        userDetails.phoneNumber = phoneNumber;
        userDetails.birthDate = birthDate;
        userDetails.status = status;

        return userDetails;
    }

    // Function to retrieve update DynamoDB user information with SSO user details.
    async updateSSOUserInfo(ssoUserDetails: BankSSOUser): Promise<void> {
        // Do not allow user to enter if he/she has not been seeded.
        let userDynamoInfo: UserDTO = await this.userService.fetchFullUserDetails(ssoUserDetails.email);

        // Update particulars
        const { given_name, family_name, phone_number, birthdate } = ssoUserDetails;
        userDynamoInfo = this.updateUserCreationObj(userDynamoInfo, given_name, family_name, phone_number, birthdate);

        // Save particulars
        await this.userService.updateUserDetails(userDynamoInfo);
    }

    async checkUserLoginMethod(orgId: string, loginMethod: LoginMethodEnum): Promise<boolean> {
        let organizationDetails: Organization | undefined = await this.orgCacheManager.get(orgId);
        if (!organizationDetails) {
            organizationDetails = await this.organizationService.fetchOrganizationDetails(orgId);
            await this.orgCacheManager.set(orgId, organizationDetails);
        }

        if (!organizationDetails.authMethod.includes(loginMethod)) {
            throw new UnauthorizedException(
                `${loginMethod} authentication method is not allowed by ${organizationDetails.name}`,
            );
        }
        return true;
    }

    async auth0Login(email: string, password: string): Promise<string> {
        if (!email || !password) {
            throw new BadRequestException("Missing email or password!");
        }

        const data: Auth0LoginDataDTO = {
            grant_type: "password",
            client_id: this.configService.get("AUTH0_CLIENT_ID") ?? "",
            client_secret: this.configService.get("AUTH0_CLIENT_SECRET") ?? "",
            username: email,
            password: password,
        };

        const encodedData = stringify(data);

        try {
            const res = await this.httpService.axiosRef.post("/oauth/token", encodedData, {
                baseURL: this.configService.get("AUTH0_BASE_URL"),
                headers: { "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8" },
            });
            return res?.data?.id_token;
        } catch (error) {
            throw new HttpException(error?.response?.data, error?.response?.status);
        }
    }
}
