import { IsEmail, IsNotEmpty, IsString } from "class-validator";

export class LoginEmailParamsDTO {
    @IsString()
    @IsNotEmpty()
    name: string;

    @IsEmail()
    @IsNotEmpty()
    email: string;
}
