import { Component } from '@angular/core';
import {RegisterRequest} from "../../models/register-request";
import {AuthenticationResponse} from "../../models/authentication-response";
import {AuthenticationService} from "../../services/authentication.service";
import {Router} from "@angular/router";
import {VerificationRequest} from "../../models/verification-request";

@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrl: './register.component.scss'
})
export class RegisterComponent{
  registerRequest:RegisterRequest={};
  authResponse:AuthenticationResponse={};
  message='';
  otpCode='';

  constructor(
    private authService:AuthenticationService,
    private router:Router ) {

  }
  registerUser() {
    this.message='';
    this.authService.register(this.registerRequest)
      .subscribe({
        next:(response:AuthenticationResponse)=>{
          if(response) {
            this.authResponse = response;
          }
          else
          {
            //inform the user that account has successfully created
            this.message="Account created successfully\n You will be redirected to the Login page in 3 seconds"
             setTimeout(()=>{
               this.router.navigate(['login'])
             },3000);
          }

        }
        }
      );
  }

  verifyTfa() {
    this.message='';
    const verifyRequest:VerificationRequest={
      email:this.registerRequest.email,
      code:this.otpCode

    };
    this.authService.verifyCode(verifyRequest)
      .subscribe({
        next:(response)=>{
              this.message="Account created successfully\n You will be redirected to the Login page in 3 seconds";
              setTimeout(()=>{
              localStorage.setItem('token',response.accessToken as string);
              this.router.navigate(['login']);
              },3000);
              }
        }

      );

  }
}
