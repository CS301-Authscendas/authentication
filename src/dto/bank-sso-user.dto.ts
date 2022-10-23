import { IsEmail, IsNotEmpty, IsString } from "class-validator";

export class BankSSOUser {
    @IsString()
    sub: string;

    @IsEmail()
    @IsNotEmpty()
    email: string;

    @IsString()
    given_name: string;

    @IsString()
    family_name: string;

    @IsString()
    name: string;

    @IsString()
    birthdate: string;

    @IsString()
    gender: string;

    @IsString()
    phone_number: string;
}
