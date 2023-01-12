#[macro_use] extern crate rocket;
extern crate chrono;

use rocket::{post, response::content, routes, serde::{Deserialize, Serialize, json::*}};
use rocket::http::{Cookie, CookieJar, SameSite};
use rocket::Request;
use rocket::fs::FileServer;
use rocket::response::Redirect;
use rocket_db_pools::{sqlx, sqlx::Row, sqlx::postgres::*, Database, Connection};
use chrono::{DateTime, TimeZone, NaiveDateTime, Utc};

use rocket_oauth2::{OAuth2, TokenResponse};
struct Google;

use rocket_dyn_templates::{Template, context};

#[derive(Database)]
#[database("tikifi")]
struct Logs(sqlx::PgPool);

#[serde(crate = "rocket::serde")]
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Event {
    uid: i64,
    name: String,
    description: String,
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

#[get("/events")]
async fn getActiveEvents(mut conn: Connection<Logs>) -> Option<String> {
    let events: Vec<Event> = sqlx::query("SELECT uid, name, description, event_date, venue, author FROM events WHERE NOW() BETWEEN start_date AND end_date AND is_draft=false")
        .map(|row: PgRow| Event {
            uid: row.get("uid"),
            name: row.get("name"),
            description: row.get("description"), 
            event_date: row.get("event_date"),
            venue: row.get("venue"),
            author: row.get("author"),
        })
        .fetch_all(&mut *conn).await.ok()?;
    Some(rocket::serde::json::to_string(&events).ok()?)
}//In case of none replace with something else please

#[get("/events/banner")]
async fn getBannerEvent(mut conn: Connection<Logs>) -> Option<String> {
    Some(rocket::serde::json::to_string(&"{uid:0,name:\"Chrismas\",venue:2,price:200,event_date:ssf}").ok()?)
}

#[get("/hello/<name>/<age>")]
fn hellos(name: &str, age: u8) -> String {
    format!("Hello, {} year old named {}!", age, name)
}

#[get("/")]
fn index() -> Template {
    Template::render("index", context! {
        foo: 123,
    })
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .attach(Logs::init())
        .mount("/", routes![getActiveEvents, google_callback, google_login, getBannerEvent, index])
        .mount("/assets", FileServer::from("./assets"))
        .attach(OAuth2::<Google>::fairing("google"))
        .attach(Template::fairing())
}