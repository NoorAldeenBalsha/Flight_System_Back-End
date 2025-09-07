import { BadRequestException, ForbiddenException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schema/user.schema';
import { Model,Types } from 'mongoose';
import { RegisterUserDto } from './dto/register-user.dto';
import { AuthProvider } from './auth/auth.provider';
import { LoginDto } from './dto/login.dto';
import { Response, Request } from 'express';
import { JWTPayloadType } from 'utilitis/types';
import { UpdateUserDto } from './dto/update-user.dto';
import { UserRole } from 'utilitis/enums';
import { RequestWithCookies } from 'utilitis/interface';
import { ResetPasswordDto } from './dto/reset-password.dto';
import * as fs from 'fs';
import * as path from 'path';
import { Buffer } from 'buffer';

@Injectable()
export class UserService {
  constructor(
    @InjectModel(User.name)
    private readonly userModel: Model<User>,
    private readonly authProvider: AuthProvider,
  ) {}
  //============================================================================
  //This for language of role
  private roleTranslations = {
    ADMIN: { en: 'Admin', ar: 'مدير' },
    PERSON: { en: 'Person', ar: 'شخص' },
  };
  //============================================================================
  //This for language of gender
  private genderTranslations = {
      male: { en: 'Male', ar: 'ذكر' },
      female: { en: 'Female', ar: 'أنثى' },
      other: { en: 'Other', ar: 'آخر' },
  };
  //============================================================================
  // Register a new user
  public async Register(registerUserDto:RegisterUserDto,lang: 'en' | 'ar' = 'en' ) {
    lang = ['en', 'ar'].includes(lang) ? lang : 'en';
    const { fullName } = registerUserDto;
    const errors: { field: string; message: string }[] = [];
    if (!fullName || typeof fullName !== 'string') {
      const msg = errors.push({field:'fullName',message:lang === 'ar'
            ? 'اسم المستخدم مطلوب ويجب أن يكون نصًا'
            : 'Username is required and must be a string',
      });
    }
    if (errors.length > 0) {
      throw new BadRequestException({
        message:
          lang === 'ar'
            ? 'يوجد أخطاء في البيانات المُدخلة'
            : 'There are validation errors',
        errors,
      });
    }
    // نعمل lowercase فقط
    registerUserDto.fullName = fullName.toLowerCase();

    return await this.authProvider.Register(registerUserDto, lang);
  };
  //============================================================================
  // Log in a user
  public async Login(loginDto: LoginDto,response: Response,lang: 'en' | 'ar' = 'en') {
      lang=['en','ar'].includes(lang)?lang:'en';

      return await this.authProvider.Login(loginDto, response,lang);
  };
  //============================================================================
  // Log out the current user
  public async logout(response: Response, req: Request, lang: 'en' | 'ar' = 'en') {
    response.clearCookie('refresh_token', {
    httpOnly: true,
      sameSite: 'none',
      secure:true,
      path: '/',
    });

    const message =
    lang === 'ar'
      ? 'تم تسجيل الخروج بنجاح'
      : 'Logged out successfully';

  return { message };
  };
  //============================================================================
  // Refresh the access token (used when the current one expires)
  public async refreshAccessToken(request:RequestWithCookies,response:Response){
      return await this.authProvider.refreshAccessToken(request,response);
  };
  //============================================================================
  // Get current user (general usage)
  public async getCurrentUser(id: Types.ObjectId,lang: 'en' | 'ar' = 'en',) {
      lang=['en','ar'].includes(lang)?lang:'en';
      const user = await this.userModel.findById(id)
      if (!user) {
        const msg = lang === 'ar' ? 'المستخدم غير موجود' : 'User not found';
        throw new NotFoundException(msg);
  }
  return {
    userName: user.fullName,
    role: this.roleTranslations[user.role]?.[lang] || user.role,
    gender: this.genderTranslations[user.gender]?.[lang] || user.gender,
    userEmail:user.email
  };
  };
  //============================================================================
  // Get all users with pagination, search, and role filtering
  public async getAllUsers(page: number = 1,limit: number = 10,search?: string,role?: string,lang: 'en' | 'ar' = 'en',) {
        lang=['en','ar'].includes(lang)?lang:'en';
        const query: any = {};
        if (search) {
          query.$or = [
            { [`userName.${lang}`]: { $regex: search, $options: 'i' } },
            { userEmail: { $regex: search, $options: 'i' } },
          ];
        }
        if (role) {
          query.role = role;
        }
        const totalUsers = await this.userModel.countDocuments(query);
        const totalPages = Math.ceil(totalUsers / limit);
        const users = await this.userModel
          .find(query)
          .select('userName userEmail role profileImage enrolledCourses gender age')
          .skip((page - 1) * limit)
          .limit(limit)
          .lean();
        const usersWithLang = users.map((u) => ({...u,
          userName: u.fullName,
          role: this.roleTranslations[u.role]?.[lang] || u.role,
          gender: this.genderTranslations[u.gender]?.[lang] || u.gender,}));
         return {success: true,totalUsers,currentPage: page,totalPages,data: usersWithLang,};
  };
  //============================================================================
  // Update user information
  public async update(id:Types.ObjectId,currentUser:JWTPayloadType,updateUserDto:UpdateUserDto,lang:'en'|'ar'='en',): Promise<User> {
    lang = ['en', 'ar'].includes(lang) ? lang : 'en';

    if (currentUser.userType !== UserRole.ADMIN) {
      const msg =
        lang === 'ar'
          ? 'غير مسموح لك بالتعديل'
          : 'You are not authorized to perform this action';
      throw new UnauthorizedException(msg);
    }

    const userFromDB = await this.userModel.findById(id);
    if (!userFromDB) {
      const msg = lang === 'ar' ? 'المستخدم غير موجود' : 'User not found';
      throw new NotFoundException(msg);
    }

    const { fullName, password, gender, phone } = updateUserDto;

    if (fullName) userFromDB.fullName = fullName;
    if (gender) userFromDB.gender = gender;
    if (phone) userFromDB.phone = phone;
    if (password) {
      userFromDB.password = await this.authProvider.hashPasswword(password);
    }

    return await userFromDB.save();
  };
  //============================================================================
  // Remove (delete) a user
  public async deleteUser(id: Types.ObjectId,currentUser: JWTPayloadType,lang: 'en' | 'ar' = 'en',):Promise<{ message: string }> {
    lang = ['en', 'ar'].includes(lang) ? lang : 'en';

    if (currentUser.userType !== UserRole.ADMIN) {
      const msg =
        lang === 'ar'
          ? 'غير مسموح لك بالحذف'
          : 'You are not authorized to perform this action';
      throw new UnauthorizedException(msg);
    }
    const deletedUser = await this.userModel.findByIdAndDelete(id);
    if (!deletedUser) {
      const msg = lang === 'ar' ? 'المستخدم غير موجود' : 'User not found';
      throw new NotFoundException(msg);
    }

    const successMsg =
      lang === 'ar'
        ? 'تم حذف المستخدم بنجاح'
        : 'User deleted successfully';

    return { message: successMsg };
  };
  //============================================================================
  // Verify user's email using a verification token
  public async verifyEmail(id: Types.ObjectId, verificationToken: string,lang: 'en' | 'ar' = 'en'): Promise<{ message: string }> {
    lang=['en','ar'].includes(lang)?lang:'en';
    const userFromDB = await this.userModel.findById(id);
    if (!userFromDB) {const msg = lang === 'ar' ? 'المستخدم غير موجود' : 'User not found';
      throw new NotFoundException(msg);}
    if (userFromDB.verificationToken === null) {
      const msg = lang === 'ar' ? 'لا توجد رمز تحقق موجود' : 'No verification token present';
      throw new NotFoundException(msg);
      }
      if (userFromDB.verificationToken !== verificationToken) {
        const msg = lang === 'ar' ? 'رمز التحقق غير صالح' : 'Invalid verification token';
      throw new NotFoundException(msg);
      }
      userFromDB.isAccountverified = true;
      userFromDB.verificationToken = null;
      await userFromDB.save();
      const msg = lang === 'ar' ? 'تم التحقق من البريد الإلكتروني بنجاح. يمكنك الآن تسجيل الدخول.' : 'Email verified successfully. You can now log in.';
      return { message: msg };
  };
  //============================================================================
  // Send a reset password link to user's email
  public async sendRestPassword(email: string,lang: 'en' | 'ar' = 'en') {
            lang=['en','ar'].includes(lang)?lang:'en';
      return await this.authProvider.SendResetPasswordCode(email,lang);
  };
  //============================================================================
  // Reset the user's password
  public async resetPassword(body: ResetPasswordDto,lang: 'en' | 'ar' = 'en') {
            lang=['en','ar'].includes(lang)?lang:'en';
      return await this.authProvider.ResetPassword(body,lang);
  };
  //============================================================================
}