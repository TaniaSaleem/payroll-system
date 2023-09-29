const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true
    },
    email: {
      type: String,
      required: true,
      unique: true
    },
    password: {
      type: String,
      required: true
    },
    role: {
      type: String,
      enum: ['user', 'admin'],
      default: 'user'
    },
    salt: {
        type: String
    }
  },
  { timestamps: true }
);

// Hash the password before saving it to the database
userSchema.pre('save', async function (next) {
  const user = this;
  if (!user.isModified('password')) return next();

  try {
    
    const salt = await bcrypt.genSalt();
    user.salt = salt; // Store the salt in the user document
    user.password = await bcrypt.hash(user.password, salt);
    next();
  } catch (error) {
    return next(error);
  }
});

// Compare the given password with the hashed password in the database
userSchema.methods.comparePassword = async function (password, salt) {  
    const hashedPassword = await bcrypt.hash(password, salt); 
    return hashedPassword === this.password;
//   };
  
//   return bcrypt.compare(hashedPass, this.password);
};

const User = mongoose.model('User', userSchema);

module.exports = User;