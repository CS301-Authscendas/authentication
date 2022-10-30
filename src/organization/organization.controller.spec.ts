import { HttpModule } from "@nestjs/axios";
import { ConfigModule } from "@nestjs/config";
import { Test, TestingModule } from "@nestjs/testing";
import { OrganizationController } from "./organization.controller";
import { OrganizationService } from "./organization.service";

describe("OrganizationController", () => {
    let controller: OrganizationController;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            imports: [ConfigModule, HttpModule, HttpModule.register({})],
            controllers: [OrganizationController],
            providers: [OrganizationService],
        }).compile();

        controller = module.get<OrganizationController>(OrganizationController);
    });

    it("should be defined", () => {
        expect(controller).toBeDefined();
    });
});
