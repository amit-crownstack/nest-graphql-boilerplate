import { Module } from '@nestjs/common';
import {
  UsersModule,
  AppointmentsModule,
  CounselorModule,
  PaymentsModule,
  PlansModule,
} from './routes';
import { ConfigModule } from '@nestjs/config';
import databaseConfig from './database/config/database-config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { DatabaseConfigService } from './database/database-config.service';
import { DataSource, DataSourceOptions } from 'typeorm';
import { AuthModule } from './routes/auth/auth.module';
import { TreatmentModule } from './routes/treatment/treatment.module';
import { ResponseFormatterService } from './common/helper_services/response_formatter.service';
import authConfig from './routes/auth/config/auth.config';
import { ServerHealthModule } from './routes/server_health/server_health.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      load: [databaseConfig, authConfig],
      isGlobal: true,
    }),
    TypeOrmModule.forRootAsync({
      useClass: DatabaseConfigService,
      dataSourceFactory: async (options: DataSourceOptions) => {
        console.log('options', options);
        return new DataSource(options).initialize();
      },
    }),
    UsersModule,
    AppointmentsModule,
    CounselorModule,
    PaymentsModule,
    PlansModule,
    AuthModule,
    TreatmentModule,
    ServerHealthModule,
  ],
  providers: [ResponseFormatterService],
})
export class AppModule {}
