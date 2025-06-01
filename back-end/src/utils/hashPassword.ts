/* eslint-disable prettier/prettier */
import * as bcrypt from 'bcrypt';

export const hashPassword = async (password: string): Promise<string> => {
  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = bcrypt.hashSync(password, salt);
    return hashedPassword;
  } catch (error: any) {
    throw new Error(error.message);
  }
};

export const comparePassword = async (password: string, hash: string) => {
  try {
    return await bcrypt.compare(password, hash);
  } catch (error) {
    throw error;
  }
};

export const hashOTP = async (otp: string): Promise<string> => {
  try {
    const salt = await bcrypt.genSalt(10);
    const hashedOTP = bcrypt.hashSync(otp, salt);
    return hashedOTP;
  } catch (error: any) {
    throw new Error(error.message);
  }
};
