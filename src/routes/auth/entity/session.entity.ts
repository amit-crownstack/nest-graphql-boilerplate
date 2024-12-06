import { Entity, Column, Index } from 'typeorm';
import { BaseEntity } from 'src/common/entity/baseEntity';

@Entity('session')
export class UserSession extends BaseEntity {
  @Column({ type: 'uuid' })
  @Index()
  userId: string;

  @Column({
    type: 'varchar',
    length: 255,
    nullable: true,
  })
  @Index()
  refreshToken: string;
}
