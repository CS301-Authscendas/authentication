import { HttpService } from "@nestjs/axios";
import {
    BadRequestException,
    HttpException,
    Inject,
    Injectable,
    InternalServerErrorException,
    Logger,
} from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { ClientProxy } from "@nestjs/microservices";
import { BankSSOUser } from "../dto/bank-sso-user.dto";

import { TokenSecretDTO } from "../dto/token-secret.dto";
import { TwoFATokenObj, UserDTO, UserStatus } from "../dto/user.dto";

@Injectable()
export class UserService {
    private BASE_URL: string;
    constructor(
        @Inject("USER_RMQ_SERVICE") private client: ClientProxy,
        private readonly httpService: HttpService,
        configService: ConfigService,
    ) {
        this.BASE_URL = configService.get("BASE_USER_URL") ?? "";
        Logger.log("UserService --- " + this.BASE_URL);
    }

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
        try {
            const res = await this.httpService.axiosRef.get(`${this.BASE_URL}/id/${userId}`);
            return res.data;
        } catch (error) {
            if (error.code === "ECONNREFUSED") {
                throw new InternalServerErrorException("Organization microservice error.");
            }
            throw new HttpException(error?.response?.data, error?.response?.status);
        }
    }

    async fetchFullUserDetails(email: string): Promise<UserDTO> {
        try {
            const res = await this.httpService.axiosRef.get(`${this.BASE_URL}/full/${email}`);
            return res?.data;
        } catch (error) {
            if (error.code === "ECONNREFUSED") {
                throw new InternalServerErrorException("Organization microservice error.");
            }
            throw new HttpException(error?.response?.data, error?.response?.status);
        }
    }

    // Function to fetch user details via email using REST API call.
    async fetchUserDetails(email: string): Promise<UserDTO> {
        try {
            const res = await this.httpService.axiosRef.get(`${this.BASE_URL}/${email}`);
            return res?.data;
        } catch (error) {
            if (error.code === "ECONNREFUSED") {
                throw new InternalServerErrorException("Organization microservice error.");
            }
            throw new HttpException(error?.response?.data, error?.response?.status);
        }
    }

    async fetchUserDetailsSSO(token: string): Promise<BankSSOUser> {
        try {
            const res = await this.httpService.axiosRef.get(`${this.BASE_URL}/oauth/userinfo`, {
                headers: {
                    Authorization: "Bearer " + token,
                },
            });
            return res?.data;
        } catch (error) {
            if (error.code === "ECONNREFUSED") {
                throw new InternalServerErrorException("Error connecting to Bank SSO.");
            }
            throw new HttpException(error?.response?.data, error?.response?.status);
        }
    }

    async updateUserDetails(userObj: UserDTO): Promise<boolean> {
        try {
            const res = await this.httpService.axiosRef.put(this.BASE_URL, userObj);
            return res?.data;
        } catch (error) {
            if (error.code === "ECONNREFUSED") {
                throw new InternalServerErrorException("Organization microservice error.");
            }
            throw new HttpException(error?.response?.data, error?.response?.status);
        }
    }

    saveTwoFactorSecret(email: string, twoFactorObj: TwoFATokenObj): void {
        const dataObj: TokenSecretDTO = {
            email: email,
            secret: twoFactorObj,
        };

        this.client.send("set-2FA-secret", dataObj).subscribe();
    }

    clearTwoFactorSecret(email: string): void {
        const dataObj = {
            email: email,
        };

        this.client.send("clear-2FA-secret", dataObj).subscribe();
    }
}
