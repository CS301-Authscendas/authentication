import {
    BadRequestException,
    HttpException,
    Injectable,
    InternalServerErrorException,
    UnauthorizedException,
} from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import * as twoFactor from "node-2fa";
import { UserDTO, UserStatus } from "../dto/user.dto";
import { NotificationService } from "../notification/notification.service";
import { UserService } from "../user/user.service";

import { HttpService } from "@nestjs/axios";
import { JwtService } from "@nestjs/jwt";
import * as bcrypt from "bcryptjs";
import { decode, verify } from "jsonwebtoken";
import { BankSSOUser } from "../dto/bank-sso-user.dto";
import { UserCreationDTO } from "../dto/user-creation.dto";
import { UserJSONPayload } from "../dto/user-json-payload.dto";
import { UserJWTData } from "../dto/user-jwt-data.dto";

@Injectable()
export class AuthService {
    constructor(
        private readonly httpService: HttpService,
        private readonly userService: UserService,
        private readonly notificationService: NotificationService,
        private readonly configService: ConfigService,
        private readonly jwtService: JwtService,
    ) {}

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
        return this.jwtService.sign(payload);
    }

    // Function to decode JWT Token.
    decodeJWTToken(jwtToken: string): UserJWTData {
        return decode(jwtToken, { complete: true }) as UserJWTData;
    }

    isJwtTokenValid(jwtToken: string, key: string): boolean {
        try {
            verify(jwtToken, key, { algorithms: ["RS256"] });
        } catch (error) {
            return false;
        }
        return true;
    }

    async checkJWTValidity(token: string): Promise<UserDTO> {
        const jwtToken: string = token.replace("Bearer", "").trim();

        // Check if token is an SSO token.
        if (this.isJwtTokenValid(jwtToken, this.configService.get("SSO_PUBLIC_KEY") ?? "")) {
            const ssoUser: BankSSOUser = await this.userService.fetchUserDetailsSSO(jwtToken);
            const dbUser: UserDTO = await this.userService.fetchUserDetails(ssoUser.email);
            return dbUser;
        }

        // Check if token is an hosted login token.
        if (this.isJwtTokenValid(jwtToken, this.configService.get("JWT_PUBLIC_KEY") ?? "")) {
            const jwtData: UserJWTData = this.decodeJWTToken(jwtToken);
            const data: UserJSONPayload = jwtData.payload as UserJSONPayload;
            const dbUser: UserDTO = await this.userService.fetchUserDetails(data.email);
            return dbUser;
        }

        throw new UnauthorizedException("Invalid JWT token.");
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
            return res?.data;
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
        const userDetails: UserDTO = await this.userService.fetchUserDetails(email);

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

    // Function to validate user credentials and request for a new 2FA token for user.
    async generate2FAToken(email: string): Promise<void> {
        const newSecret = twoFactor.generateSecret();

        if (newSecret == null || newSecret.secret == null) {
            throw new InternalServerErrorException("Error generating 2FA secret");
        }

        const userDetails: UserDTO = await this.userService.fetchUserDetails(email);

        const name = `${userDetails.firstName} ${userDetails.lastName}`;

        const token2 = Math.floor(100000 + Math.random() * 900000);

        // Save 2FA secret via Organizations microservice.
        this.userService.saveTwoFactorSecret(email, token2.toString());

        const newToken = twoFactor.generateToken(newSecret.secret);

        if (!newToken?.token) {
            throw new InternalServerErrorException("Error generating 2FA token");
        }

        // Send 2FA token via Notifications microservice.
        this.notificationService.trigger2FATokenEmail(name, email, token2.toString());
    }

    // Function to validate input 2FA token using secret generated for user and return a new JWT token.
    async validate2FAToken(email: string, token: string): Promise<boolean> {
        const userDetails: UserDTO = await this.userService.fetchUserDetails(email);
        const userSecret = userDetails.twoFATokenSecret;

        this.userService.clearTwoFactorSecret(email);

        if (!userSecret) {
            throw new InternalServerErrorException(`${email} does not have a 2FA secret.`);
        }

        return userSecret === token;
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
        let userDynamoInfo: UserDTO = await this.userService.fetchUserDetails(ssoUserDetails.email);

        // Update particulars
        const { given_name, family_name, phone_number, birthdate } = ssoUserDetails;
        userDynamoInfo = this.updateUserCreationObj(userDynamoInfo, given_name, family_name, phone_number, birthdate);

        // Save particulars
        await this.userService.updateUserDetails(userDynamoInfo);
    }
}
