import { Entity, Column, Index } from 'typeorm';
import { VerificationType } from './enum/verification-type.enum';
import { VerificationStatus } from './enum/verification-status.enum';
import { BaseEntity } from 'src/common/entity/baseEntity';

@Entity('user_verification')
export class UserVerificationEntity extends BaseEntity {
  @Column({ type: 'uuid', nullable: false })
  @Index()
  user_id: string;

  @Column({
    type: 'enum',
    enum: VerificationType,
  })
  verificationType: string;

  @Column({
    type: 'enum',
    enum: VerificationStatus,
    default: VerificationStatus.PENDING,
  })
  status: string;

  @Column({
    type: 'varchar',
    length: 255,
    nullable: true,
  })
  @Index()
  token: string;

  @Column({
    type: 'varchar',
    length: 255,
    unique: true,
  })
  otpSecret: string;

  @Column({ type: 'timestamp', nullable: true })
  expiresAt: Date;

  // Methods to check token validity
  isExpired(): boolean {
    return this.expiresAt ? new Date() > this.expiresAt : false;
  }

  isValid(): boolean {
    return this.status === VerificationStatus.PENDING && !this.isExpired();
  }
}
