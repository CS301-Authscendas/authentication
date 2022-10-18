import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { ClientProvider, RmqContext, RmqOptions, Transport } from "@nestjs/microservices";

@Injectable()
export class MqService {
    constructor(private readonly configService: ConfigService) {}

    private transportMethod = this.configService.get<string>("RABBITMQ_TRANSPORT_METHOD");
    private user = this.configService.get<string>("RABBITMQ_USER");
    private password = this.configService.get<string>("RABBITMQ_PASSWORD");
    private host = this.configService.get<string>("RABBITMQ_HOST");
    private port = this.configService.get<string>("RABBITMQ_PORT");

    getOptions(queueName: string, noAck = false): RmqOptions {
        return {
            transport: Transport.RMQ,
            options: {
                urls: [`${this.transportMethod}://${this.user}:${this.password}@${this.host}:${this.port}`],
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
                urls: [`${this.transportMethod}://${this.user}:${this.password}@${this.host}:${this.port}`],
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
