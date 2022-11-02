import { CacheModule, Module } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";
import { KmsService } from "./kms.service";

@Module({
    imports: [ConfigModule, CacheModule.register({ isGlobal: true, ttl: 15 })],
    providers: [KmsService],
    exports: [KmsService],
})
export class KmsModule {}
