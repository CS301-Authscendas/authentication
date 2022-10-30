import { HttpModule } from "@nestjs/axios";
import { ConfigModule } from "@nestjs/config";
import { Test, TestingModule } from "@nestjs/testing";
import { OrganizationService } from "./organization.service";

describe("OrganizationService", () => {
    let service: OrganizationService;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            imports: [ConfigModule, HttpModule, HttpModule.register({})],
            providers: [OrganizationService],
        }).compile();

        service = module.get<OrganizationService>(OrganizationService);
    });

    it("should be defined", () => {
        expect(service).toBeDefined();
    });
});
