import { HttpService } from "@nestjs/axios";
import { HttpException, Inject, Injectable, Logger } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { ClientProxy } from "@nestjs/microservices";
import { catchError, lastValueFrom, map } from "rxjs";
import { TokenSecretDTO } from "src/dto/token-secret.dto";
import { UserDTO } from "src/dto/user.dto";

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
            this.httpService.get(`http://${baseUrl}?email=${email}`).pipe(
                map((response) => {
                    return response?.data;
                }),
                catchError((e) => {
                    throw new HttpException(e.response.data, e.response.status);
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

    async getTwoFactorSecret(email: string): Promise<string | null> {
        // Fetch user details and return 2FA secret.
        const userDetails: UserDTO = await this.fetchUserDetails(email);

        return userDetails.twoFATokenSecret;
    }

    async signup(email: string): Promise<any> {
        // TODO:
        // Generate 2FA
        // 2FA authentication for email ownership
        try {
            const userDetails = this.fetchUserDetails(email);
            Logger.log(userDetails);
        } catch (error) {
            return error;
        }

        // Fetch user via email to check if user has been seeded
        // Store user credentials in the database

        return "Hello";
    }
}
