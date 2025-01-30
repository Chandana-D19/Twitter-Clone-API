const express = require('express')
const sqlite3 = require('sqlite3')
const {open} = require('sqlite')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()
app.use(express.json())

const dbPath = 'twitterClone.db'
let db = null

// Initialize Database and Server
const initializeDBAndServer = async () => {
  try {
    db = await open({filename: dbPath, driver: sqlite3.Database})
    console.log('Database connected')
  } catch (error) {
    console.error(`DB Error: ${error.message}`)
    process.exit(1)
  }
}
initializeDBAndServer()

// Middleware for Authentication
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization']
  if (authHeader === undefined) return res.status(401).send('Invalid JWT Token')

  const token = authHeader.split(' ')[1]
  jwt.verify(token, 'MY_SECRET_KEY', (err, payload) => {
    if (err) return res.status(401).send('Invalid JWT Token')

    req.userId = payload.userId
    next()
  })
}

// API 1: User Registration
app.post('/register/', async (req, res) => {
  const {username, password, name, gender} = req.body
  const hashedPassword = await bcrypt.hash(password, 10)

  const userExists = await db.get(
    `SELECT * FROM user WHERE username = ?`,
    username,
  )
  if (userExists) return res.status(400).send('User already exists')

  if (password.length < 6) return res.status(400).send('Password is too short')

  await db.run(
    `INSERT INTO user (name, username, password, gender) VALUES (?, ?, ?, ?)`,
    name,
    username,
    hashedPassword,
    gender,
  )
  res.send('User created successfully')
})

// API 2: User Login
app.post('/login/', async (req, res) => {
  const {username, password} = req.body
  const user = await db.get(`SELECT * FROM user WHERE username = ?`, username)

  if (!user) return res.status(400).send('Invalid user')
  const isPasswordCorrect = await bcrypt.compare(password, user.password)
  if (!isPasswordCorrect) return res.status(400).send('Invalid password')

  const token = jwt.sign({userId: user.user_id}, 'MY_SECRET_KEY')
  res.send({jwtToken: token})
})

// API 3: Get Latest Tweets from Followed Users (Limit 4)
app.get('/user/tweets/feed/', authenticateToken, async (req, res) => {
  const query = `
    SELECT username, tweet, date_time AS dateTime 
    FROM tweet INNER JOIN user ON tweet.user_id = user.user_id
    WHERE tweet.user_id IN (SELECT following_user_id FROM follower WHERE follower_user_id = ?)
    ORDER BY date_time DESC LIMIT 4;
  `
  const tweets = await db.all(query, req.userId)
  res.send(tweets)
})

// API 4: Get List of Users Followed by the Current User
app.get('/user/following/', authenticateToken, async (req, res) => {
  const query = `
    SELECT name FROM user 
    WHERE user_id IN (SELECT following_user_id FROM follower WHERE follower_user_id = ?);
  `
  const following = await db.all(query, req.userId)
  res.send(following)
})

// API 5: Get Followers of the Current User
app.get('/user/followers/', authenticateToken, async (req, res) => {
  const query = `
    SELECT name FROM user 
    WHERE user_id IN (SELECT follower_user_id FROM follower WHERE following_user_id = ?);
  `
  const followers = await db.all(query, req.userId)
  res.send(followers)
})

// API 6: Get Tweet Details (Only for Followed Users)
app.get('/tweets/:tweetId/', authenticateToken, async (req, res) => {
  const {tweetId} = req.params

  const tweet = await db.get(
    `
    SELECT tweet, date_time AS dateTime FROM tweet 
    WHERE tweet_id = ? AND user_id IN 
      (SELECT following_user_id FROM follower WHERE follower_user_id = ?)
  `,
    tweetId,
    req.userId,
  )

  if (!tweet) return res.status(401).send('Invalid Request')

  const likes = await db.get(
    `SELECT COUNT(*) AS likes FROM like WHERE tweet_id = ?`,
    tweetId,
  )
  const replies = await db.get(
    `SELECT COUNT(*) AS replies FROM reply WHERE tweet_id = ?`,
    tweetId,
  )

  res.send({...tweet, ...likes, ...replies})
})

// API 7: Get Users Who Liked a Tweet
app.get('/tweets/:tweetId/likes/', authenticateToken, async (req, res) => {
  const {tweetId} = req.params

  const likedUsers = await db.all(
    `
    SELECT username FROM user 
    WHERE user_id IN (SELECT user_id FROM like WHERE tweet_id = ?)
  `,
    tweetId,
  )

  if (!likedUsers.length) return res.status(401).send('Invalid Request')

  res.send({likes: likedUsers.map(user => user.username)})
})

// API 8: Get Replies to a Tweet
app.get('/tweets/:tweetId/replies/', authenticateToken, async (req, res) => {
  const {tweetId} = req.params

  const replies = await db.all(
    `
    SELECT name, reply FROM user 
    INNER JOIN reply ON user.user_id = reply.user_id 
    WHERE reply.tweet_id = ?
  `,
    tweetId,
  )

  if (!replies.length) return res.status(401).send('Invalid Request')

  res.send({replies})
})

// API 9: Get All Tweets of the Logged-in User
app.get('/user/tweets/', authenticateToken, async (req, res) => {
  const tweets = await db.all(
    `
    SELECT tweet, COUNT(DISTINCT like.like_id) AS likes, COUNT(DISTINCT reply.reply_id) AS replies, tweet.date_time AS dateTime
    FROM tweet 
    LEFT JOIN like ON tweet.tweet_id = like.tweet_id
    LEFT JOIN reply ON tweet.tweet_id = reply.tweet_id
    WHERE tweet.user_id = ?
    GROUP BY tweet.tweet_id
  `,
    req.userId,
  )
  res.send(tweets)
})

// API 10: Create a Tweet
app.post('/user/tweets/', authenticateToken, async (req, res) => {
  const {tweet} = req.body
  await db.run(
    `INSERT INTO tweet (tweet, user_id, date_time) VALUES (?, ?, datetime('now'))`,
    tweet,
    req.userId,
  )
  res.send('Created a Tweet')
})

// API 11: Delete a Tweet
app.delete('/tweets/:tweetId/', authenticateToken, async (req, res) => {
  const {tweetId} = req.params

  const tweet = await db.get(
    `SELECT * FROM tweet WHERE tweet_id = ? AND user_id = ?`,
    tweetId,
    req.userId,
  )
  if (!tweet) return res.status(401).send('Invalid Request')

  await db.run(`DELETE FROM tweet WHERE tweet_id = ?`, tweetId)
  res.send('Tweet Removed')
})

module.exports = app
