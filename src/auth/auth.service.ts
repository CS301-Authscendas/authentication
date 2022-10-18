import { BadRequestException, Injectable, UnauthorizedException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import * as twoFactor from "node-2fa";
import { UserDTO, UserStatus } from "../dto/user.dto";
import { NotificationService } from "../notification/notification.service";
import { UserService } from "../user/user.service";

import * as bcrypt from "bcrypt";
import * as jwt from "jsonwebtoken";
import JwksRsa, { JSONWebKey, JwksClient } from "jwks-rsa";
import { UserCreationDTO } from "../dto/user-creation.dto";
import { UserJSONPayload } from "../dto/user-json-payload.dto";
import { UserJWTData } from "../dto/user-jwt-data.dto";

@Injectable()
export class AuthService {
    private client: JwksClient;
    constructor(
        private readonly userService: UserService,
        private readonly notificationService: NotificationService,
        private readonly configService: ConfigService,
    ) {
        // Verify using getKey callback
        // Example uses https://github.com/auth0/node-jwks-rsa as a way to fetch the keys.
        this.client = new JwksClient({
            jwksUri: this.configService.get("JWKS_URI") ?? "",
            cache: true,
            rateLimit: true,
        });
    }

    async hashPassword(password: string): Promise<string> {
        const salt = await bcrypt.genSalt(10);
        return await bcrypt.hash(password, salt);
    }

    private async comparePassword(hashedPassword: string, unhashedPassword: string): Promise<boolean> {
        return await bcrypt.compare(unhashedPassword, hashedPassword);
    }

    private async generateJWTToken(payload: UserJSONPayload): Promise<string> {
        const keys: JSONWebKey[] = (await this.client.getKeys()) as JSONWebKey[];
        const header = keys[Math.round(Math.random() * (keys.length - 1))];
        const key: JwksRsa.SigningKey = await this.client.getSigningKey(header.kid);

        return jwt.sign(payload, key.getPublicKey(), {
            expiresIn: "1d",
            algorithm: "HS256",
            keyid: header.kid,
        });
    }

    async decodeJWTToken(jwtToken: string): Promise<UserJWTData> {
        try {
            const payload = jwt.decode(jwtToken, { complete: true }) as UserJWTData;
            const secret = await this.client.getSigningKey(payload.header.kid);
            jwt.verify(jwtToken, secret.getPublicKey(), { algorithms: ["HS256"] });

            return payload;
        } catch (error) {
            throw new UnauthorizedException("Invalid JWT token.");
        }
    }

    async generate2FAToken(email: string): Promise<boolean> {
        const newSecret = twoFactor.generateSecret();

        if (newSecret == null || newSecret.secret == null) {
            return false;
        }

        const userDetails: UserDTO = await this.userService.fetchUserDetails(email);

        const name = `${userDetails.firstName} ${userDetails.lastName}`;

        // Save 2FA secret via Organizations microservice.
        this.userService.saveTwoFactorSecret(email, newSecret.secret);

        const newToken = twoFactor.generateToken(newSecret.secret);

        if (!newToken?.token) {
            return false;
        }

        // Send 2FA token via Notifications microservice.
        this.notificationService.trigger2FATokenEmail(name, email, newToken.token);
        return true;
    }

    async validate2FAToken(email: string, token: string): Promise<boolean> {
        const userSecret = await this.userService.getTwoFactorSecret(email);

        if (!userSecret) {
            return false;
        }

        const tokenValidWindow: number = this.configService.get("TOKEN_WINDOW") ?? 1;
        const results = twoFactor.verifyToken(userSecret, token, tokenValidWindow);
        return results?.delta != null && results.delta == 0;
    }

    async signupRequest2FAToken(email: string): Promise<boolean> {
        // Fetch user, check if user has already signed up before.
        const userDetails: UserDTO = await this.userService.fetchUserDetails(email);

        if (userDetails.status === UserStatus.Approved) {
            throw new BadRequestException("User has already signed up");
        }

        // Generate 2FA and send 2FA token.
        return await this.generate2FAToken(email);
    }

    async hostedLogin(email: string, password: string): Promise<string> {
        const userDetails: UserDTO = await this.userService.fetchUserDetails(email);
        const hashedPassword: string = userDetails.password;
        const success = await this.comparePassword(hashedPassword, password);

        const payload: UserJSONPayload = {
            id: userDetails.id,
            role: userDetails.role,
        };

        if (!success) {
            throw new UnauthorizedException("Invalid password");
        }

        return await this.generateJWTToken(payload);
    }

    async signup(userCreationObj: UserCreationDTO): Promise<boolean> {
        const email = userCreationObj.email;

        const userDetails: UserDTO = await this.userService.fetchUserDetails(email);

        // Hash the plain text password
        userDetails.password = await this.hashPassword(userCreationObj.password);

        // Update particulars
        userDetails.firstName = userCreationObj.firstName;
        userDetails.lastName = userCreationObj.lastName;
        userDetails.phoneNumber = userCreationObj.phoneNumber;
        userDetails.birthDate = userCreationObj.birthDate;
        userDetails.status = UserStatus.Approved;

        // Save particulars
        return await this.userService.updateUserDetails(userDetails);
    }
}
