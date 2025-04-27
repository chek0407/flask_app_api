# ⚽ EPL Teams & Players API

This API allows you to access and manage English Premier League (EPL) data, including teams and their players. Built with Flask, hosted on AWS EC2, using DynamoDB for storage.

---

## 🔐 Authentication

All endpoints require a valid JWT token.

**How to authenticate:**

```http
Authorization: Bearer <your_token>
```

---

## 📚 Endpoints

### 1. `GET /epl/teams`
Returns detailed information for all EPL teams.

**Example Response:**
```json
[
  {
    "TeamID": "AVL",
    "EntityType": "TEAM",
    "Founded": 1874,
    "Manager": "Unai Emery",
    "Stadium": "Villa Park",
    "TeamName": "Aston Villa"
  }
]
```

---

### 2. `GET /epl/teams/<team_id>` — with filters and sorting
Returns players for a specific team, with optional filters and sorting.

#### 🔎 Query Parameters:

| Param     | Description |
|-----------|-------------|
| `position` | Filter by position (e.g., `GK`, `CF`, `CM`) |
| `min_age`  | Minimum player age (e.g., `25`) |
| `max_age`  | Maximum player age (e.g., `30`) |
| `number`   | Filter by exact jersey number (e.g., `9`) |
| `sort_by`  | Field to sort by: `age`, `number`, `PlayerName`, `Position` |
| `order`    | Sort direction: `asc` (default) or `desc` |

#### 🧪 Example Request:
```
GET /epl/teams/MCI?position=GK&min_age=28&sort_by=age&order=desc
```

#### ✅ Example Response:
```json
[
  {
    "PlayerName": "Ederson",
    "Position": "GK",
    "Jersey#": 31,
    "Age": 31,
    "Nationality": "Brazil"
  },
  {
    "PlayerName": "Stefan Ortega",
    "Position": "GK",
    "Jersey#": 18,
    "Age": 30,
    "Nationality": "Germany"
  }
]
```

---

### 3. `GET /epl/teams/<team_id>/details`
Returns detailed team info + full squad.

**Example Response:**
```json
{
  "team": {
    "TeamID": "AVL",
    "TeamName": "Aston Villa",
    "Founded": 1874,
    "Manager": "Unai Emery",
    "Stadium": "Villa Park"
  },
  "players": [
    {
      "PlayerName": "Emiliano Martínez",
      "Position": "GK",
      "Jersey#": 1,
      "Age": 32,
      "Nationality": "Argentina"
    }
  ]
}
```

---

### 4. `GET /epl/player/search?q=<name>`
Searches players by name.

**Example Request:**
```
GET /epl/player/search?q=haaland
```

**Response:**
```json
[
  {
    "PlayerName": "Erling Haaland",
    "Team": "MCI",
    "Position": "CF",
    "Jersey#": 9,
    "Age": 24
  }
]
```

---

### 5. `POST /epl/player`
Adds a new player.

**Request Body:**
```json
{
  "Team": "CHE",
  "Jersey#": 10,
  "PlayerName": "New Player",
  "Position": "RW",
  "Age": 25,
  "Nationality": "England"
}
```

**Response:**
```json
{
  "message": "Player added successfully"
}
```

---

### 6. `PUT /epl/player/<team_id>/<jersey_number>`
Updates a player’s info.

**Example Request:**
```
PUT /epl/player/ARS/7
```

**Body:**
```json
{
  "Position": "CM",
  "Age": 26
}
```

---

### 7. `DELETE /epl/player/<team_id>/<jersey_number>`
Deletes a player by team and jersey number.

**Example Request:**
```
DELETE /epl/player/MCI/9
```

---

## 🚨 Errors & Status Codes

| Code | Message        | Meaning                       |
|------|----------------|-------------------------------|
| 200  | OK             | Request succeeded             |
| 400  | Bad Request    | Missing or invalid data       |
| 401  | Unauthorized   | Token missing or invalid      |
| 404  | Not Found      | Team or player not found      |
| 500  | Server Error   | Unexpected internal issue     |

---

## 🛠 Technologies Used

- **Flask + Flask-RESTX** (API framework)
- **Docker** (packaged and deployed on EC2)
- **DynamoDB** (NoSQL storage)
- **JWT Auth** (authentication)
- **AWS EC2** (deployment)

---

## 📬 Contact

Author: Vladi  
Project status: In development
