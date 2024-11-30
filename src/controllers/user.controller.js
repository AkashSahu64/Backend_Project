import {asyncHandler} from '../utils/asyncHandler.js';
import {ApiError} from '../utils/ApiError.js'
import {User} from '../models/user.model.js'
import {uploadOnCloudinary} from '../utils/cloudinary.js'
import {ApiResponse} from '../utils/ApiResponse.js'


const generateAccessAndRefreshTokens = async (usrId) => {
    try {
        const user = await User.findById(usrId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        //refresh tokensave in db
        user.refreshToken = refreshToken
        await user.save({validateBeforeSave: false})
        return {accessToken, refreshToken}
    } catch (error) {
        throw new ApiError(500, "Somthing went wrong white generating refresh and access token")
    }
}

//user registration
const registerUser = asyncHandler(async (req, res) => {
    //get user details from frontend
    const {fullName, email, username, password} = req.body
    // console.log("Email: ", email);
    
    if ([fullName, email, username, password].some((field) => field?.trim() === '')) {
        throw new ApiError(400, 'All fiels are required')
    }

    // check if user already exists 
    const existedUser = await User.findOne({
        $or: [{username}, {email}]
    })
    if(existedUser){
        throw new ApiError(409, 'Username or Email already exists')
    }

    //cheks for images 
    const avatarLocalPath = req.files?.avatar[0]?.path;
    // const coverImageLocalPath = req.files?.coverImage[0]?.path;
    let coverImageLocalPath;
    if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0){
        coverImageLocalPath = req.files.coverImage[0].path
    }

    if(!avatarLocalPath){
        throw new ApiError(400, 'Avatar file is required')
    }

    //upload images on cloudinary
    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)
    if(!avatar){
        throw new ApiError(400, 'Avatar file is required')
    }

    //cretae user object and entry in db
    const user = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase()
    }) 

    //remove password and refreshToken field from response
    const createdUser = await User.findById(user._id).select(
        '-password -refreshToken'
    )
    //check for user creation
    if(!createdUser){
        throw new ApiError(500, "Something went wrong while registring the user")
    }

    //return response
    return res.status(201).json(
        new ApiResponse(200, createdUser, "User registered successfully.")
    )
})

//user login
const loginUser = asyncHandler(async (req,res) => {
    //mine the data from req body
    const {email, username, password} = req.body;
    if(!username || !email) {
        throw new ApiError(400, 'Username or email is required')
    }

    const user = await User.findOne({
        $or: [{username}, {email}]
    })
    if(!user){
        throw new ApiError(404, 'User does not exist.')
    }

    const isPasswordValid = await user.isPasswordCorret(password)
    if(!isPasswordValid){
        throw new ApiError(401, 'Invalid user credentials')
    }

    const {accessToken, refreshToken} = await generateAccessAndRefreshTokens(user._id)

    const loggedInUser = await User.findById(user._id).select('-password -refreshToken')

    //sending cookies
    const options = { //not changeable through url
        httpOnly: true,
        secure: true
    }
    return res.status(200)
    .cookie('accessToken', accessToken, options)
    .cookie('refreshToken', refreshToken, options)
    .json(
        new ApiResponse( 200,
            {
                user: loggedInUser, accessToken, refreshToken
            },
            "User logged In successfully"
        )
    )
})

const logoutUser = asyncHandler(async (req, res) => {
    await User.findByIdAndUpdate(req.user._id,
        {
            $set: {
                refreshToken: undefined
            }
        },
        {
            new: true // for new updated value
        }
    )

    const options = {
        httpOnly: true,
        secure: true
    }
    return res.status(200)
    .clearCookies('accessToken', options)
    .clearCookies('refreshToken', options)
    .json(new ApiResponse(200, {}, "User looged Out"))
})

export {registerUser, loginUser, logoutUser}