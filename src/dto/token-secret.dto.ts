import { IsEmail, IsNotEmpty } from "class-validator";
import { TwoFATokenObj } from "./user.dto";

export class TokenSecretDTO {
    @IsEmail()
    @IsNotEmpty()
    email: string;

    @IsNotEmpty()
    secret: TwoFATokenObj;
}
