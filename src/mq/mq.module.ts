import { Module } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";
import { MqService } from "./mq.service";

@Module({
    imports: [ConfigModule.forRoot()],
    providers: [MqService],
    exports: [MqService],
})
export class MqModule {}
