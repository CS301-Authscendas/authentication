import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { ClientProvider, RmqContext, RmqOptions, Transport } from "@nestjs/microservices";

@Injectable()
export class MqService {
    constructor(private readonly configService: ConfigService) {}

    getOptions(queueName: string, noAck = false): RmqOptions {
        const transportMethod = this.configService.get<string>("RABBITMQ_TRANSPORT_METHOD");
        const user = this.configService.get<string>("RABBITMQ_USER");
        const password = this.configService.get<string>("RABBITMQ_PASSWORD");
        const host = this.configService.get<string>("RABBITMQ_HOST");
        const port = this.configService.get<string>("RABBITMQ_PORT");

        return {
            transport: Transport.RMQ,
            options: {
                urls: [`${transportMethod}://${user}:${password}@${host}:${port}`],
                queue: queueName,
                noAck,
                persistent: true,
            },
        };
    }

    getClientProvider(queueName: string): ClientProvider {
        return {
            transport: Transport.RMQ,
            options: {
                urls: [
                    `${this.configService.get<string>("RABBITMQ_TRANSPORT_METHOD")}://${this.configService.get<string>(
                        "RABBITMQ_USER",
                    )}:${this.configService.get<string>("RABBITMQ_PASSWORD")}@${this.configService.get<string>(
                        "RABBITMQ_HOST",
                    )}:${this.configService.get<string>("RABBITMQ_PORT")}`,
                ],
                queue: queueName,
                queueOptions: {
                    durable: true,
                },
            },
        };
    }

    ack(context: RmqContext) {
        const channel = context.getChannelRef();
        const originalMessage = context.getMessage();
        channel.ack(originalMessage);
    }
}
