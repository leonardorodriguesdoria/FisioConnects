/* eslint-disable prettier/prettier */
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { OTP } from '../entities/otp.entity';
import { OTPService } from './otp.serivce';
import { JwtModule } from '@nestjs/jwt';

@Module({
  imports: [TypeOrmModule.forFeature([OTP]), JwtModule],
  providers: [OTPService],
  exports: [OTPService],
})
export class OTPModule {}
