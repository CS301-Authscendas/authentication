import { IsEmail, IsNotEmpty, IsString } from "class-validator";

export class TokenSecretDTO {
    @IsEmail()
    @IsNotEmpty()
    email: string;

    @IsString()
    @IsNotEmpty()
    secret: string;
}
