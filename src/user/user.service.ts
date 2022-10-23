import { HttpService } from "@nestjs/axios";
import { Inject, Injectable, InternalServerErrorException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { ClientProxy } from "@nestjs/microservices";
import { catchError, lastValueFrom, map } from "rxjs";
import { BankSSOUser } from "src/dto/bank-sso-user.dto";

import { TokenSecretDTO } from "../dto/token-secret.dto";
import { UserDTO, UserRole } from "../dto/user.dto";

@Injectable()
export class UserService {
    constructor(
        @Inject("USER_RMQ_SERVICE") private client: ClientProxy,
        private readonly httpService: HttpService,
        private readonly configService: ConfigService,
    ) {}

    // Function to fetch user detail via REST API call to Organization service.
    async fetchUserDetails(email: string): Promise<UserDTO> {
        const baseUrl = this.configService.get("BASE_USER_URL");
        return await lastValueFrom(
            this.httpService.get(`${baseUrl}?email=${email}`).pipe(
                map((response) => {
                    return response?.data;
                }),
                catchError(() => {
                    throw new InternalServerErrorException(`Failed to fetch user details: ${email}`);
                }),
            ),
        );
    }

    async fetchUserDetailsSSO(token: string): Promise<BankSSOUser> {
        const baseUrl = this.configService.get("SSO_BASE_URL");
        return await lastValueFrom(
            this.httpService
                .get(`${baseUrl}/oauth/userinfo`, {
                    headers: {
                        Authorization: "Bearer " + token,
                    },
                })
                .pipe(
                    map((response) => {
                        return response?.data;
                    }),
                    catchError(() => {
                        throw new InternalServerErrorException(`Failed to fetch SSO user`);
                    }),
                ),
        );
    }

    async updateUserDetails(userObj: UserDTO): Promise<boolean> {
        const baseUrl = this.configService.get("BASE_USER_URL");
        return await lastValueFrom(
            this.httpService.put(baseUrl, userObj).pipe(
                map((response) => {
                    return response?.data;
                }),
                catchError(() => {
                    throw new InternalServerErrorException(`Failed to update user details: ${userObj.email}`);
                }),
            ),
        );
    }

    saveTwoFactorSecret(email: string, twoFactorSecret: string): void {
        const dataObj: TokenSecretDTO = {
            email: email,
            secret: twoFactorSecret,
        };

        this.client.send("set-2FA-secret", dataObj).subscribe();
    }

    // Question: Can i put this into a user class? To avoid fetching multiple times for the same request.
    // Possible solution: Maybe i can overload these method?
    async getTwoFactorSecret(email: string): Promise<string | null> {
        // Fetch user details and return 2FA secret.
        const userDetails: UserDTO = await this.fetchUserDetails(email);

        return userDetails.twoFATokenSecret;
    }

    async getUserRole(email: string): Promise<UserRole> {
        // Fetch user details and return 2FA secret.
        const userDetails: UserDTO = await this.fetchUserDetails(email);

        return userDetails.role;
    }
}
