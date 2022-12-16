#[macro_use] extern crate rocket;
extern crate chrono;

use rocket::{post, response::content, routes, serde::{Deserialize, Serialize, json::*}};
use rocket::http::{Cookie, CookieJar, SameSite};
use rocket::Request;
use rocket::response::Redirect;
use rocket_db_pools::{sqlx, sqlx::Row, sqlx::postgres::*, Database, Connection};
use chrono::{DateTime, TimeZone, NaiveDateTime, Utc};

use rocket_oauth2::{OAuth2, TokenResponse};
struct Google;

#[derive(Database)]
#[database("tikifi")]
struct Logs(sqlx::PgPool);

#[serde(crate = "rocket::serde")]
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Event {
    uid: i64,
    name: String,
    description: String,
    price: f64,
    event_date: DateTime<Utc>,
    venue: i64,
    author: i64,
}

#[get("/login/google")]
fn google_login(oauth2: OAuth2<Google>, cookies: &CookieJar<'_>) -> Redirect {
    oauth2.get_redirect(cookies, &["profile"]).unwrap()
}

#[get("/auth/google")]
fn google_callback(token: TokenResponse<Google>, cookies: &CookieJar<'_>) -> Redirect
{
    cookies.add_private(
        Cookie::build("token", token.access_token().to_string())
            .same_site(SameSite::Lax)
            .finish()
    );
    Redirect::to("/")
}

#[post("/events", format = "json", data = "<data>")]
fn addEvent(data: rocket::serde::json::Json<Event>) -> std::io::Result<String> {
    Ok(format!("Hello!"))
}

//Test ASYNC BLEEED MAKE EVERYTHING ELSE ASYNC BABY
#[get("/events")]
async fn getActiveEvents(mut conn: Connection<Logs>) -> Option<String> {
    let events: Vec<Event> = sqlx::query("SELECT uid, name, description, price, event_date, venue, author FROM events WHERE NOW() BETWEEN start_date AND end_date AND is_draft=false")
        .map(|row: PgRow| Event {
            uid: row.get("uid"),
            name: row.get("name"),
            description: row.get("description"), 
            price: row.get("price"),
            event_date: row.get("event_date"),
            venue: row.get("venue"),
            author: row.get("author"),
        })
        .fetch_all(&mut *conn).await.ok()?;
    Some(rocket::serde::json::to_string(&events).ok()?)
}

#[get("/hello/<name>/<age>")]
fn hellos(name: &str, age: u8) -> String {
    format!("Hello, {} year old named {}!", age, name)
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .attach(Logs::init())
        .mount("/", routes![getActiveEvents, google_callback, google_login])
        .attach(OAuth2::<Google>::fairing("google"))
}