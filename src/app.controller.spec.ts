import { ConfigModule } from "@nestjs/config";
import { Test, TestingModule } from "@nestjs/testing";
import { AppController } from "./app.controller";
import { AppService } from "./app.service";
import { MqModule } from "./mq/mq.module";
import { NotificationModule } from "./notification/notification.module";
import { UserModule } from "./user/user.module";
import { UserService } from "./user/user.service";

describe("AppController", () => {
    let appController: AppController;

    beforeEach(async () => {
        const app: TestingModule = await Test.createTestingModule({
            imports: [ConfigModule.forRoot({ isGlobal: true }), UserModule, NotificationModule, MqModule],
            controllers: [AppController],
            providers: [UserService, AppService],
        }).compile();

        appController = app.get<AppController>(AppController);
    });

    describe("root", () => {
        it('should return "Auth service is awake!"', () => {
            expect(appController.healthCheck()).toBe("Auth service is awake!");
        });
    });
});
