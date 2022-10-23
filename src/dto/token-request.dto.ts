import { IsEmail, IsNotEmpty, IsString } from "class-validator";

export class TokenRequestDTO {
    @IsEmail()
    @IsNotEmpty()
    email: string;

    @IsString()
    @IsNotEmpty()
    token: string;
}
