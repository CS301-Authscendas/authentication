import { HttpService } from "@nestjs/axios";
import { HttpException, Injectable, InternalServerErrorException, UnauthorizedException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { LoginMethodEnum } from "src/dto/login-method.enum";
import { Organization } from "src/dto/organization.dto";

@Injectable()
export class OrganizationService {
    constructor(private readonly configService: ConfigService, private readonly httpService: HttpService) {}

    // Function to fetch organization details via id through REST API call.
    async fetchOrganizationDetails(organizationId: string): Promise<Organization> {
        const baseUrl = this.configService.get("BASE_ORGANIZATION_URL") ?? "";
        try {
            const res = await this.httpService.axiosRef.get(`${baseUrl}/${organizationId}`);
            return res?.data;
        } catch (error) {
            if (error.code === "ECONNREFUSED") {
                throw new InternalServerErrorException("Organization microservice error.");
            }
            throw new HttpException(error?.response?.data, error?.response?.status);
        }
    }

    async checkUserLoginMethod(orgId: string, loginMethod: LoginMethodEnum): Promise<boolean> {
        const organizationDetails: Organization = await this.fetchOrganizationDetails(orgId);

        if (!(loginMethod in organizationDetails.authMethod)) {
            throw new UnauthorizedException(`${loginMethod} is not allowed by ${organizationDetails.name}`);
        }

        return true;
    }
}
