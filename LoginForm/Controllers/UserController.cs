using LoginForm.Context;
using LoginForm.Helpers;
using LoginForm.Model;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;
using System;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authorization;

namespace LoginForm.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {

        public readonly UserDBConetext _dbContext;


        public UserController(UserDBConetext userDBConetext)
        {
            _dbContext = userDBConetext;
        }


        [HttpPost("authenticate")]

        public async Task<IActionResult> Authenticate([FromBody] User userobj)
        {
            if (userobj == null)
            {
                return BadRequest();
            }

            var obj = await _dbContext.Users.FirstOrDefaultAsync(x => x.UserName == userobj.UserName);

            if (obj == null)
            {
                return NotFound(new
                {
                    Message = "User Not Found"
                });
            }

            if (!(PasswordHasher.VerifyPassword(userobj.Password, obj.Password)))
            {
                return BadRequest(new
                {
                    Message = "Password is Incorrect"
                });
            }

            obj.Token = CreateJwt(obj);


            return Ok(new
            {

                token = obj.Token,

                //obj= obj.UserName,obj.Password,

                Message = "SuccessFully Login"

            });
        }




        [HttpPost("Registered")]

        public async Task<IActionResult> Registered([FromBody] User user)
        {
            if (user == null)
            {
                return BadRequest();
            }

            ////UserName

            if (await CheckUserNameExists(user.UserName))
            {

                return BadRequest(new
                {
                    Message = "User Already Exists"
                });

            }

            //Email
            if (await CheckPassExists(user.Email))
            {

                return BadRequest(new
                {
                    Message = "Email Already Exists"
                });

            }

            //password
            var str = CheckPasswordHasher(user.Password);
            if (!(string.IsNullOrEmpty(str)))
            {
                return BadRequest(new
                {
                    Message = str.ToString()
                });
            }
            {

            }




            user.Password = PasswordHasher.Hashpassword(user.Password);

            user.Role = "User";
            user.Token = "";

            await _dbContext.Users.AddAsync(user);

            await _dbContext.SaveChangesAsync();

            return Ok(new
            {
                Message = "SuccessFully Registered"
            });
        }

        //[Authorize]

        [HttpGet]

        public async Task<IActionResult> GetAllUser()
        {
            var con =await _dbContext.Users.ToListAsync();
            return Ok(con);
        }











        private Task<bool> CheckUserNameExists(string username)
        {

            return _dbContext.Users.AnyAsync(x => x.UserName == username);
        }

        private Task<bool> CheckPassExists(string email)
        {
            return _dbContext.Users.AnyAsync(x => x.Email == email);
        }

        private string CheckPasswordHasher(string password)
        {

            StringBuilder sb = new StringBuilder();

            if (password.Length < 8)
            {
                sb.Append("Minimun Password Length should be 8" + Environment.NewLine);
            }
            if (!(Regex.IsMatch(password, "[a-z]") && Regex.IsMatch(password, "[A-Z]") && Regex.IsMatch(password, "[1-9]")))
            {
                sb.Append("Letter Should Contain AlphaNumberic" + Environment.NewLine);
            }
            if (!(Regex.IsMatch(password, "[<,>,/,?,.,!,@,#,$,%,^,&,*,(,),_,-,+,=,[,{,}]")))
            {
                sb.Append("Special Letters Mandatory" + Environment.NewLine);
            }

            return sb.ToString();
        }

 

public class KeyGenerator
    {
        public static byte[] GenerateKey(int keySizeInBits)
        {
            byte[] keyBytes = new byte[keySizeInBits / 8]; 
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(keyBytes);
            }
            return keyBytes;
        }
    }


    private string CreateJwt(User user)
        {
            var JwtTokenHandler = new JwtSecurityTokenHandler();
            var key = KeyGenerator.GenerateKey(256);
           // var key = Encoding.ASCII.GetBytes("verysecret....");
            var identity = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Role, user.Role),
                new Claim(ClaimTypes.Name, $"{user.FirstName},{user.LastName}")
            });

            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);

            var TokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.Now.AddSeconds(10),
                SigningCredentials = credentials

            };
            var token = JwtTokenHandler.CreateToken(TokenDescriptor);
            return JwtTokenHandler.WriteToken(token);

        }
    }
}
