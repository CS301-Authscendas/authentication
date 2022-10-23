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
import * as bcrypt from "bcrypt";
import { decode, JwtPayload, sign, verify } from "jsonwebtoken";
import JwksRsa, { JSONWebKey, JwksClient } from "jwks-rsa";
import { BankSSOUser } from "src/dto/bank-sso-user.dto";
import { UserCreationDTO } from "../dto/user-creation.dto";
import { UserJSONPayload } from "../dto/user-json-payload.dto";
import { UserJWTData } from "../dto/user-jwt-data.dto";

@Injectable()
export class AuthService {
    private client: JwksClient;
    constructor(
        private readonly httpService: HttpService,
        private readonly userService: UserService,
        private readonly notificationService: NotificationService,
        private readonly configService: ConfigService,
    ) {
        // Verify using getKey callback
        this.client = new JwksClient({
            jwksUri: this.configService.get("JWKS_URI") ?? "",
            cache: true,
            rateLimit: true,
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

    // Function to generate JWT Token, encoding a JSON payload and key ID from JWKs.
    private async generateJWTToken(payload: UserJSONPayload): Promise<string> {
        const keys: JSONWebKey[] = (await this.client.getKeys()) as JSONWebKey[];
        const header = keys[Math.round(Math.random() * (keys.length - 1))];
        const key: JwksRsa.SigningKey = await this.client.getSigningKey(header.kid);

        return (
            "Bearer " +
            sign(payload, key.getPublicKey(), {
                expiresIn: "1d",
                algorithm: "HS256",
                keyid: header.kid,
            })
        );
    }

    // Function to decode JWT Token.
    decodeJWTToken(jwtToken: string): UserJWTData {
        return decode(jwtToken, { complete: true }) as UserJWTData;
    }

    // Function to authenticate JWT Token by verifying with public key in JWKs.
    async authenticateJWTToken(jwtToken: string): Promise<UserJWTData> {
        const token = jwtToken?.replace("Bearer", "")?.trim();
        try {
            const payload: UserJWTData = this.decodeJWTToken(token);
            const secret = await this.client.getSigningKey(payload.header.kid);
            verify(jwtToken, secret.getPublicKey(), { algorithms: ["HS256"] });

            return payload;
        } catch (error) {
            throw new UnauthorizedException("Invalid JWT token.");
        }
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

    // Function to decode SSO token using using Bank SSO public key.
    decodeSSOJWTToken(jwtToken: string): JwtPayload {
        // Read public key from PEM file.
        const publicKey = this.configService.get("SSO_PUBLIC_KEY");
        const strippedToken = jwtToken?.replace("Bearer", "")?.trim();

        try {
            return verify(strippedToken, publicKey, { complete: true, algorithms: ["RS256"] });
        } catch (e) {
            throw new UnauthorizedException(e);
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
        return await this.userService.updateUserDetails(userDetails);
    }

    // Function to validate user credentials and request for a new 2FA token for user.
    async hostedLogin(email: string, password: string): Promise<boolean> {
        const userDetails: UserDTO = await this.userService.fetchUserDetails(email);

        if (userDetails.status !== UserStatus.Approved) {
            throw new UnauthorizedException("User has not signed up!");
        }

        const hashedPassword: string = userDetails.password;
        const success = await this.comparePassword(hashedPassword, password);

        if (!success) {
            throw new UnauthorizedException("Invalid password");
        }

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

        // Save 2FA secret via Organizations microservice.
        this.userService.saveTwoFactorSecret(email, newSecret.secret);

        const newToken = twoFactor.generateToken(newSecret.secret);

        if (!newToken?.token) {
            throw new InternalServerErrorException("Error generating 2FA token");
        }

        // Send 2FA token via Notifications microservice.
        this.notificationService.trigger2FATokenEmail(name, email, newToken.token);
    }

    // Function to validate input 2FA token using secret generated for user and return a new JWT token.
    async validate2FAToken(email: string, token: string): Promise<string> {
        const userDetails: UserDTO = await this.userService.fetchUserDetails(email);
        const userSecret = userDetails.twoFATokenSecret;

        if (!userSecret) {
            throw new InternalServerErrorException(`${email} does not have a 2FA secret.`);
        }

        const tokenValidWindow: number = this.configService.get("TOKEN_WINDOW") ?? 1;
        const results = twoFactor.verifyToken(userSecret, token, tokenValidWindow);
        if (results?.delta != null && results.delta == 0) {
            // If 2FA token is valid, generate JWT Token and send login notification.
            const payload: UserJSONPayload = {
                id: userDetails.id,
                email: userDetails.email,
            };

            const jwtToken = await this.generateJWTToken(payload);

            const name = `${userDetails.firstName} ${userDetails.lastName}`;

            this.notificationService.triggerLoginAlertEmail(name, email);

            return jwtToken;
        }

        return "";
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
