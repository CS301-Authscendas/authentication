import { Body, Controller, Post, Response } from "@nestjs/common";
import { Response as Res } from "express";
import { LoginMethodCheckDTO } from "../dto/login-method-check.dto";
import { OrganizationService } from "./organization.service";

@Controller("organization")
export class OrganizationController {
    constructor(private readonly organizationService: OrganizationService) {}

    @Post("validate-login-method")
    async checkLoginMethodValidity(@Body() requestBody: LoginMethodCheckDTO, @Response() res: Res): Promise<Res> {
        const success = await this.organizationService.checkUserLoginMethod(
            requestBody.organizationId,
            requestBody.loginMethod,
        );
        return res.json({ success: success });
    }
}
