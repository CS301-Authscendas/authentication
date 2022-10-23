import { HttpService } from "@nestjs/axios";
import { BadRequestException, Inject, Injectable, InternalServerErrorException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { ClientProxy } from "@nestjs/microservices";
import { catchError, lastValueFrom, map } from "rxjs";
import { BankSSOUser } from "src/dto/bank-sso-user.dto";

import { TokenSecretDTO } from "../dto/token-secret.dto";
import { UserDTO, UserRole, UserStatus } from "../dto/user.dto";

@Injectable()
export class UserService {
    constructor(
        @Inject("USER_RMQ_SERVICE") private client: ClientProxy,
        private readonly httpService: HttpService,
        private readonly configService: ConfigService,
    ) {}

    // Function to fetch user email via user ID used during magic link sign up.
    async fetchEmailMagicLink(userId: string): Promise<string> {
        const userInfo: UserDTO = await this.fetchUserDetailsById(userId);
        if (userInfo.status === UserStatus.Approved) {
            throw new BadRequestException("User has already signed up!");
        }

        return userInfo.email;
    }

    // Function to fetch user details via user ID using REST API call.
    async fetchUserDetailsById(userId: string): Promise<UserDTO> {
        const baseUrl = this.configService.get("BASE_USER_URL");
        return await lastValueFrom(
            this.httpService.get(`${baseUrl}/id/${userId}`).pipe(
                map((response) => {
                    return response?.data;
                }),
                catchError(() => {
                    throw new InternalServerErrorException(`Failed to fetch user details from id: ${userId}`);
                }),
            ),
        );
    }

    // Function to fetch user details via email using REST API call.
    async fetchUserDetails(email: string): Promise<UserDTO> {
        const baseUrl = this.configService.get("BASE_USER_URL");
        return await lastValueFrom(
            this.httpService.get(`${baseUrl}/${email}`).pipe(
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

    async getUserRole(email: string): Promise<UserRole> {
        // Fetch user details and return 2FA secret.
        const userDetails: UserDTO = await this.fetchUserDetails(email);

        return userDetails.role;
    }
}
