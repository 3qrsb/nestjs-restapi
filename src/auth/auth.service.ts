import { Injectable } from '@nestjs/common';

@Injectable({})
export class AuthService {
  signup() {
    return { msg: 'signup msg' };
  }

  signin() {
    return 'signin msg';
  }
}
