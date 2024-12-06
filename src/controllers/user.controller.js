import {asyncHandler} from '../utils/asyncHandler.js';
import {ApiError} from '../utils/ApiError.js'
import {User} from '../models/user.model.js'
import {uploadOnCloudinary} from '../utils/cloudinary.js'
import {ApiResponse} from '../utils/ApiResponse.js'
import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';


const generateAccessAndRefreshTokens = async (usrId) => {
    try {
        const user = await User.findById(usrId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefeshToken()

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
    if(!(username || email)) {
        throw new ApiError(400, 'Username or email is required')
    }

    const user = await User.findOne({
        $or: [{username}, {email}]
    })
    if(!user){
        throw new ApiError(404, 'User does not exist.')
    }

    const isPasswordValid = await user.isPasswordCorrect(password)
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
    .clearCookie('accessToken', options)
    .clearCookie('refreshToken', options)
    .json(new ApiResponse(200, {}, "User looged Out"))
})

//login with refresh token
const refreshAccessToken = asyncHandler(async (req, res) => {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken
    if(!incomingRefreshToken){
        throw new ApiError(401, 'Unauthorished request')
    }

    try {
        const decodedToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        )
    
        const user = await User.findById(decodedToken?._id)
        if(!user){
            throw new ApiError(401, "Invalid Refresh Token.")
        }
    
        if(incomingRefreshToken != user?.refreshToken){
            throw new ApiError(401, 'Refresh token is expired or used.')
        }
        //sending in cookies
        const options = {
            httpOnly: true,
            secure: true
        }
        const {accessToken, newRefreshToken} = await generateAccessAndRefreshTokens(user._id)
        return res(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", newRefreshToken, options)
        .json(new ApiResponse(200, {accessToken, refreshToken: newRefreshToken},
            'Access token refreshed'
        ))
    } catch (error) {
        throw new ApiError(401, error?.message || 'Invalid refresh token.')
    }
})

//User password changing
const changeCurrentPassword = asyncHandler(async (req, res) => {
    const {oldPassword, newPassword} = req.body
    const user = await User.findById(req.body?._id) //error?
    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

    if(!isPasswordCorrect){
        throw new ApiError(400, 'Invalid old password')
    }
    user.password = newPassword
    await user.save({validateBeforeSave: false})
    return res.status(200).json(new ApiResponse(200, {}, 'Password Change successfully'))
})

//getting current user
const getCurrentUser = asyncHandler(async (req, res) =>{
    return res.status(200)
    .json(new ApiResponse(200, req.user, 'Current user feched successfully.'))
})

//Update user account details
const updateAccountDetails = asyncHandler(async (req, res) =>{
    const {fullName, email} = req.body
    if(!fullName || !email){
        throw new ApiError(400, 'All feilds are required')
    }

    const user = await User.findByIdAndUpdate(req.body?._id,
        {
            $set: {
                fullName,
                email
            }
        }, {new :true}
    ).select("-password")

    return res.status(200)
    .json(new ApiResponse(200, user, 'Account updated Successfully'))
})

//Update avatar Image files
const updateUserAvatar = asyncHandler (async (req, res) =>{
    const avatarLocalPath = req.file?.path
    if(!avatarLocalPath){
        throw new ApiError(400, 'Avatar file is not found')
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)
    if(!avatar.url){
        throw new ApiError(400, "Error while uploading avatar")
    }

    const user = await User.findByIdAndUpdate(req.user?._id,
        {
            $set:{
                avatar: avatar.url
            }
        },
        {new: true}
    ).select("-password")

    return res.status(200)
    .json(new ApiResponse(200, user, 'Avatar image uploaded succesfully.'))
})

//update cover image file
const updateUserCoverImage = asyncHandler (async (req, res) =>{
    const coverImageLocalPath = req.file?.path
    if(!coverImageLocalPath){
        throw new ApiError(400, 'Cover image file is not found')
    }

    const coverImage = await uploadOnCloudinary(coverImageLocalPath)
    if(!coverImage.url){
        throw new ApiError(400, "Error while uploading cover image")
    }

    const user = await User.findByIdAndUpdate(req.user?._id,
        {
            $set:{
                coverImage: coverImage.url
            }
        },
        {new: true}
    ).select("-password")

    return res.status(200)
    .json(new ApiResponse(200, user, 'Cover image uploaded succesfully.'))
})

const getUserChannelProfile = asyncHandler(async (req, res) => {
    const {username} = req.params
    if(!username?.trim()){
        throw new ApiError(400, 'Username missing')
    }

    const channel = await User.aggregate([
        {
            $match: {
                username: username.toLowerCase()
            }
        },
        {
            $lookup: {
                from: "subscriptons",
                localField: "_id",
                foreignField: "channel",
                as: "subscribers"
            }
        },
        {
            $lookup: {
                from: "subscriptons",
                localField: "_id",
                foreignField: "subscriber",
                as: "subscriberedTo"
            }
        },
        {
            $addFields: {
                subscribersCount: {
                    $size: "$subscribers"
                },
                channelSubscribedToCount: {
                    $size: "$subscriberedTo"
                },
                isSubscribed: {
                    $cond: {
                        if: {$in: [req.user?._id, "$subscribers.subscriber"]},
                        then: true,
                        else: false
                    }
                }
            }
        },
        {
            $project: {
                fullName: 1,
                username: 1,
                channelSubscribedToCount: 1,
                isSubscribed: 1,
                avatar: 1,
                coverImage: 1,
                email: 1
            }
        }
    ])

    if(!channel?.length){
        throw new ApiError(404, "Channel does not exists.")
    }
    return res.status(200)
    .json(new ApiResponse(200, channel[0], "User channel fetched successfully."))
})

//get watch history
const getWatchHistory = asyncHandler(async(req, res) =>{
    const user = await User.aggregate([
        {
            $match: {
                _id: new mongoose.Types.ObjectId(req.user._id)
            }
        },
        {
            $lookup: {
                from: 'videos',
                localField: 'watchHistory',
                foreignField: '_id',
                as: 'watchHistory',
                pipeline: [
                    {
                        $lookup: {
                            from: 'users',
                            localField: 'owner',
                            foreignField: '_id',
                            as: 'owner',
                            pipeline: [
                                {
                                    $project:{
                                        fullName: 1,
                                        username: 1,
                                        avatar: 1
                                    }
                                }
                            ]
                        }
                    },
                    {
                        $addFields: {
                            owner: {
                                $first: '$owner'
                            }
                        }
                    }
                ]
            }
        }
    ])

    returnres.status(200)
    .json(new ApiResponse(200, user[0].watchHistory, 'watch history fetched successfully.'))
})

export {
    registerUser, loginUser, logoutUser,
    refreshAccessToken, changeCurrentPassword,
    getCurrentUser, updateAccountDetails,
    updateUserAvatar, updateUserCoverImage, getUserChannelProfile,
    getWatchHistory
}