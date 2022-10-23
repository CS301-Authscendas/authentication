import { IsEmail, IsNotEmpty, IsString } from "class-validator";

export class LoginCredentialsDTO {
    @IsEmail()
    @IsNotEmpty()
    email: string;

    @IsString()
    @IsNotEmpty()
    password: string;
}
