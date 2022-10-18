import { HttpModule } from "@nestjs/axios";
import { Module } from "@nestjs/common";
import { ConfigModule, ConfigService } from "@nestjs/config";
import { ClientsModule } from "@nestjs/microservices";
import { MqModule } from "../mq/mq.module";
import { MqService } from "../mq/mq.service";
import { UserService } from "./user.service";

@Module({
    imports: [
        HttpModule,
        ConfigModule,
        MqModule,
        ClientsModule.registerAsync([
            {
                name: "USER_RMQ_SERVICE",
                imports: [MqModule, ConfigModule],
                inject: [MqService, ConfigService],
                useFactory: (mqService: MqService, configService: ConfigService) =>
                    mqService.getClientProvider(configService.get("USER_QUEUE_NAME") ?? ""),
            },
        ]),
    ],
    providers: [UserService],
    exports: [UserService],
})
export class UserModule {}
