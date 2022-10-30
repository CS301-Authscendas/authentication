import { Module } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";
import { AppController } from "./app.controller";
import { AuthModule } from "./auth/auth.module";
import { MqModule } from "./mq/mq.module";
import { NotificationModule } from "./notification/notification.module";
import { OrganizationModule } from "./organization/organization.module";
import { UserModule } from "./user/user.module";

@Module({
    imports: [
        ConfigModule.forRoot({ isGlobal: true }),
        UserModule,
        NotificationModule,
        MqModule,
        AuthModule,
        OrganizationModule,
    ],
    controllers: [AppController],
    providers: [],
})
export class AppModule {}
