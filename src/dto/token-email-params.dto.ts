import { IsEmail, IsNotEmpty, IsString } from "class-validator";

export class TokenEmailParamsDTO {
    @IsString()
    @IsNotEmpty()
    name: string;

    @IsEmail()
    @IsNotEmpty()
    email: string;

    @IsString()
    @IsNotEmpty()
    code: string;
}
