import { Module } from '@nestjs/common';
import { UsersController } from './users.controller';
import { UsersService } from './provider/user.service';
import { UserEntity } from './entity/user.entity';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserSession } from '../auth/entity/session.entity';

@Module({
  imports: [TypeOrmModule.forFeature([UserEntity, UserSession])],
  controllers: [UsersController],
  providers: [UsersService],
  exports: [UsersService],
})
export class UsersModule {}
