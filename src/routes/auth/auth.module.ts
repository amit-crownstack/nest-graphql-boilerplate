import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserEntity } from '../users/entity/user.entity';
import { AuthController } from './auth.controller';
import { AuthService } from './provider/auth.service';
import { ResponseFormatterService } from 'src/common/helper_services/response_formatter.service';
import { UsersService } from '../users/provider/user.service';

@Module({
  imports: [TypeOrmModule.forFeature([UserEntity])],
  controllers: [AuthController],
  providers: [AuthService, ResponseFormatterService, UsersService],
})
export class AuthModule {}
