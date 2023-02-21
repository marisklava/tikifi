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

use rocket_dyn_templates::{Template, context, tera::Context};

/*extern crate oauth2;
use oauth2::{basic::{BasicClient, BasicErrorResponseType, BasicTokenType}, revocation::StandardRevocableToken, StandardErrorResponse, StandardTokenResponse, RevocationErrorResponseType, EmptyExtraTokenFields, StandardTokenIntrospectionResponse, /*TokenResponse*/};
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
    RevocationUrl, Scope, TokenUrl, IntrospectionUrl
};*/

use jwksclient2::error::Error;
use jwksclient2::keyset::KeyStore;

#[derive(Database)]
#[database("tikifi")]
struct Logs(sqlx::PgPool);

#[serde(crate = "rocket::serde")]
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EventSubmission {
    name: String,
    description: String,
    start_date: DateTime<Utc>,
    end_date: DateTime<Utc>,
    event_date: DateTime<Utc>,
    is_draft: bool,
    venue: i64,
    author: i64,
}

#[derive(FromForm)]
pub struct VenueSubmission<'r> {
    name: String,
    description: String,
    location: String,
    thumbnail: rocket::fs::TempFile<'r>,
}

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

#[serde(crate = "rocket::serde")]
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Listing {
    uid: i64,
    name: String,
    event_date: DateTime<Utc>,
    venue_id: i64,
    venue_name: String,
}

#[serde(crate = "rocket::serde")]
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Venue {
    uid: i64,
    name: String,
    description: String,
    capacity: i64,
    address: String,
}

async fn get_current_user(cookies: &CookieJar<'_>) -> Option<String> {
    match cookies.get_private("token") { 
        Some(te) => {
            let jkws_url = "https://www.googleapis.com/oauth2/v3/certs";
            let key_set = KeyStore::new_from(jkws_url.to_owned()).await.unwrap();
        
            match key_set.verify(&te.value().to_string().clone()) {
                Ok(jwt) => {
                    return Some(jwt.payload().get_str("sub").expect("Expected sub value").to_owned())
                }
                Err(Error { msg, typ: _ }) => {
                    eprintln!("Could not verify token. Reason: {}", msg);
                    return None
                }
            };
        },
        None => return None,
    }
}

#[get("/login/google")]
async fn google_login(oauth2: OAuth2<Google>, cookies: &CookieJar<'_>) -> Redirect {
    
    /*let (auth_url, csrf_token) = oauth_client().await
    .authorize_url(CsrfToken::new_random)
    .add_scope(Scope::new("https://www.googleapis.com/auth/userinfo.profile".to_string()))
    .url();

    Redirect::to(auth_url.to_string())*/
    oauth2.get_redirect(cookies, &["profile"]).unwrap()
}

#[get("/auth/google")]
async fn google_callback(token: TokenResponse<Google>, cookies: &CookieJar<'_>) -> Redirect
{
    let to = token.as_value().get("id_token").expect("invalid ID token");
    let ts = to.as_str().expect("invalid ID token").to_string();

    cookies.add_private(
        Cookie::build("token", ts.clone())
            .same_site(SameSite::Lax)
            .finish()
    );

    //println!("{}", ts.clone());

    Redirect::to("/")
}

#[post("/events", format = "json", data = "<data>")]
async fn add_event(data: rocket::serde::json::Json<EventSubmission>, mut conn: Connection<Logs>) -> std::io::Result<String> {
    let a = sqlx::query("INSERT INTO public.events(
        name, description, start_date, end_date, event_date, is_draft, venue, author)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)")
    .bind(&data.name)
    .bind(&data.description)
    .bind(&data.start_date)
    .bind(&data.end_date)
    .bind(&data.event_date)
    .bind(&data.is_draft)
    .bind(&data.venue)
    .bind(&data.author)
    .execute(&mut *conn).await.ok();
    Ok(format!("Hello!"))
}

#[post("/venues", data = "<data>")]
async fn add_venue(data: rocket::form::Form<VenueSubmission<'_>>, mut conn: Connection<Logs>) -> std::io::Result<String> {
    let a = sqlx::query("INSERT INTO public.venues(
        name, description, address, capacity)
        VALUES ($1, $2, $3, 999)")
    .bind(&data.name)
    .bind(&data.description)
    .bind(&data.location)
    .execute(&mut *conn).await.ok();
    Ok(format!("Hello!"))
}

#[get("/events")]
async fn get_active_events(mut conn: Connection<Logs>) -> Option<String> {
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

async fn get_event_listings(mut conn: Connection<Logs>) -> Option<Vec<Listing>> {
    Some(sqlx::query("SELECT e.uid, e.name, e.event_date, e.venue AS venue_id, v.name AS venue_name FROM events AS e JOIN venues AS v ON e.venue = v.uid WHERE NOW() BETWEEN start_date AND end_date AND e.is_draft=false")
        .map(|row: PgRow| Listing {
            uid: row.get("uid"),
            name: row.get("name"),
            event_date: row.get("event_date"), //need to figure out datetime formatting
            venue_id: row.get("venue_id"),
            venue_name: row.get("venue_name"),
        })
        .fetch_all(&mut *conn).await.ok()?)
}

async fn get_events(mut conn: Connection<Logs>) -> Option<Vec<Listing>> {
    Some(sqlx::query("SELECT e.uid, e.name, e.event_date, e.venue AS venue_id, v.name AS venue_name FROM events AS e JOIN venues AS v ON e.venue = v.uid WHERE NOW() BETWEEN start_date AND end_date AND e.is_draft=false")
        .map(|row: PgRow| Listing {
            uid: row.get("uid"),
            name: row.get("name"),
            event_date: row.get("event_date"), //need to figure out datetime formatting
            venue_id: row.get("venue_id"),
            venue_name: row.get("venue_name"),
        })
        .fetch_all(&mut *conn).await.ok()?)
}

#[get("/venues/<id>")]
async fn get_venue(mut conn: Connection<Logs>, id: i64) -> Option<Template> {
    let venue: Venue = sqlx::query("SELECT uid, name, description, capacity, address FROM venues WHERE uid = $1").bind(id)
        .map(|row: PgRow| Venue {
            uid: row.get("uid"),
            name: row.get("name"),
            description: row.get("description"), //need to figure out datetime formatting
            capacity: row.get("capacity"),
            address: row.get("address"),
        })
        .fetch_one(&mut *conn).await.ok()?;
    Some(Template::render("venue", context! {
        venue: venue,
    }))
}

#[get("/")]
async fn index(mut conn: Connection<Logs>, cookies: &CookieJar<'_>) -> Option<Template> {
    println!("{:?}",get_current_user(cookies).await);
    let events: Vec<Listing> = get_event_listings(conn).await?; 
    let mut ctx = Context::new();
    ctx.insert("events", &events);
    ctx.insert("logged_in", &true); //?
    match cookies.get("token") { //?
        Some(c) => ctx.insert("token", &c.to_string()), //?
        None => {} //?
    }; //?
    Some(Template::render("index", ctx.into_json()))
}

#[get("/dashboard/venues")]
async fn dashboard_venues(mut conn: Connection<Logs>, cookies: &CookieJar<'_>) -> Option<Template> {
    Some(Template::render("dashboard_venues", context! {

    }))
}

#[get("/dashboard/events")]
async fn dashboard_events(mut conn: Connection<Logs>, cookies: &CookieJar<'_>) -> Option<Template> {
    let events: Vec<Listing> = get_event_listings(conn).await?; 
    let mut ctx = Context::new();
    ctx.insert("events", &events);
    ctx.insert("logged_in", &true); //?
    match cookies.get("token") { //?
        Some(c) => ctx.insert("token", &c.to_string()), //?
        None => {} //?
    }; //?
    Some(Template::render("dashboard_events", ctx.into_json()))
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .attach(Logs::init())
        .mount("/", routes![get_active_events, google_callback, google_login, index, dashboard_venues, dashboard_events, get_venue, add_event, add_venue])
        .mount("/assets", FileServer::from("./assets"))
        .attach(OAuth2::<Google>::fairing("google"))
        .attach(Template::fairing())
}