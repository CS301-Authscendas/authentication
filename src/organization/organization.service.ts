import { HttpService } from "@nestjs/axios";
import { HttpException, Injectable, InternalServerErrorException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { Organization } from "../dto/organization.dto";

@Injectable()
export class OrganizationService {
    private BASE_URL: string;
    constructor(private readonly configService: ConfigService, private readonly httpService: HttpService) {
        this.BASE_URL =
            this.configService.get("NODE_ENV") === "production"
                ? this.configService.get("PRODUCTION_ORGANIZATION_URL") ?? ""
                : this.configService.get("BASE_ORGANIZATION_URL") ?? "";
    }

    // Function to fetch organization details via id through REST API call.
    async fetchOrganizationDetails(organizationId: string): Promise<Organization> {
        try {
            const res = await this.httpService.axiosRef.get(`${this.BASE_URL}/${organizationId}`);
            return res?.data;
        } catch (error) {
            if (error.code === "ECONNREFUSED") {
                throw new InternalServerErrorException("Organization microservice error.");
            }
            throw new HttpException(error?.response?.data, error?.response?.status);
        }
    }
}
