/* eslint-disable prettier/prettier */
import { Physiotherapist } from 'src/entities/physiotherapist.entity';
import {
  Column,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
  Entity,
  CreateDateColumn,
} from 'typeorm';
import { OtpTypes } from '../otp/types/otpType';

@Entity()
export class OTP {
  @PrimaryGeneratedColumn()
  id: number;

  @ManyToOne(() => Physiotherapist, { nullable: false })
  @JoinColumn()
  physiotherapist: Physiotherapist;

  @Column()
  token: string;

  @Column({ type: 'enum', enum: OtpTypes })
  type: OtpTypes;

  @Column()
  expiresAt: Date;

  @CreateDateColumn()
  createdAt: Date;
}
