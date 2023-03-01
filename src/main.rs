#[macro_use] extern crate rocket;
extern crate chrono;

use rocket::{post, response::content, routes, serde::{Deserialize, Serialize, json::*}};
use rocket::http::{Cookie, CookieJar, SameSite};
use rocket::Request;
use rocket::fs::FileServer;
use rocket::response::Redirect;
use rocket_db_pools::{sqlx::{self, Row, postgres::*, query_builder::QueryBuilder, Execute, pool::PoolConnection}, Database, Connection};

use chrono::{DateTime, TimeZone, NaiveDateTime, Utc};

use rocket_oauth2::{OAuth2, TokenResponse};
struct Google;

use rocket_dyn_templates::{Template, context, tera::Context};

use jwksclient2::{error::Error, jwt::Payload};
use jwksclient2::keyset::KeyStore;

use bevy_reflect::Reflect;

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

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(crate = "rocket::serde")]
pub struct Event {
    uid: i64,
    name: String,
    description: String,
    event_date: DateTime<Utc>,
    venue_id: i64,
    venue_name: String,
    thumbnail_url: String,
    price: i64,
}

#[derive(Default, Debug)]
struct EventFilterCriteria {
    uid: Option<i64>,
    venue_name: Option<String>,
    event_date: Option<DateTime<Utc>>,
    venue_id: Option<i64>,
    is_draft: bool,
    is_active: bool, //UNIMPLEMENTED
    limit: Option<i32>,
}

impl EventFilterCriteria {
    fn new() -> EventFilterCriteria {
        EventFilterCriteria { ..Default::default() }
    }

    async fn exec_query(self, mut conn: &mut PoolConnection<Postgres>) -> Result<Vec<Event>, rocket_db_pools::sqlx::Error> {
        fn sep(c: i32) -> String {
            if(c==1) { return " WHERE ".to_string() }
            else { return " AND ".to_string() }
        }

        let mut q = QueryBuilder::new("SELECT ev.uid, ev.name, ev.description, ev.event_date, ev.price, ev.thumbnail_url, ev.venue AS venue_id, ven.name AS venue_name FROM events AS ev JOIN venues AS ven ON ev.venue = ven.uid");
        
        if(self.uid.is_some()) { q.push(" AND ev.uid = "); q.push_bind(self.uid.unwrap());};
        if(self.venue_id.is_some()) { q.push(" AND ev.venue = "); q.push_bind(self.venue_id.unwrap());};
        if(self.limit.is_some()) { q.push(" LIMIT "); q.push_bind(self.limit.unwrap());};

        q.build().map(|row: PgRow| Event {
            uid: row.get("uid"),
            name: row.get("name"),
            description: row.get("description"),
            event_date: row.get("event_date"), //need to figure out datetime formatting
            venue_id: row.get("venue_id"),
            venue_name: row.get("venue_name"),
            thumbnail_url: row.get("thumbnail_url"),
            price: row.get("price"),
        }).fetch_all(&mut *conn).await
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(crate = "rocket::serde")]
pub struct Venue {
    uid: i64,
    name: String,
    description: String,
    capacity: i64,
    address: String,
    thumbnail_url: String,
}

#[derive(FromForm)]
pub struct VenueSubmission<> {
    name: String,
    description: String,
    capacity: i64,
    address: String,
    thumbnail_url: String,
}
//thumbnail: rocket::fs::TempFile<'r>,

#[derive(Default, Debug)]
struct VenueFilterCriteria {
    uid: Option<i64>,
    owner: Option<String>,
    name: Option<String>,
    description: Option<String>,
    capacity: Option<i64>,
    address: Option<String>,
}

impl VenueFilterCriteria {
    fn new() -> VenueFilterCriteria {
        VenueFilterCriteria { ..Default::default() }
    }
    async fn exec_query(self, mut conn: &mut PoolConnection<Postgres>) -> Result<Vec<Venue>, rocket_db_pools::sqlx::Error> {
        fn sep(c: i32) -> String {
            if(c==1) { return " WHERE ".to_string() }
            else { return " AND ".to_string() }
        }

        let mut q = QueryBuilder::new("SELECT ven.uid, ven.name, ven.description, ven.capacity, ven.address, ven.thumbnail_url FROM venues AS ven WHERE true=true");
        
        if(self.uid.is_some()) { q.push(" AND uid = "); q.push_bind(self.uid.unwrap());};
        if(self.owner.is_some()) { q.push(" AND owner = "); q.push_bind(self.owner.unwrap());};

        q.build().map(|row: PgRow| Venue {
            uid: row.get("uid"),
            name: row.get("name"),
            description: row.get("description"),
            capacity: row.get("capacity"),
            address: row.get("address"),
            thumbnail_url: row.get("thumbnail_url"),
        }).fetch_all(&mut *conn).await

    }
}

#[derive(Serialize, Debug)]
#[serde(crate = "rocket::serde")]
pub struct UserInfo {
    id: String,
    avatar: String,
}

async fn get_current_user(cookies: &CookieJar<'_>) -> Option<UserInfo> {
    match cookies.get_private("token") { 
        Some(te) => {
            return jwks_verify_token(te.value().to_string().clone()).await
        },
        None => return None,
    }
}

async fn jwks_verify_token(token: String) -> Option<UserInfo> {
    let jkws_url = "https://www.googleapis.com/oauth2/v3/certs";
    let key_set = KeyStore::new_from(jkws_url.to_owned()).await.unwrap();

    match key_set.verify(&token) {
        Ok(jwt) => {
            let payload = jwt.payload();
            return Some(
                UserInfo {
                    id: payload.get_str("sub").expect("Expected sub value").to_owned(),
                    avatar: payload.get_str("picture").expect("Expected picture value").to_owned(),
                }
            )
        }
        Err(Error { msg, typ: _ }) => {
            eprintln!("Could not verify token. Reason: {}", msg);
            return None
        }
    };
}

#[get("/login/google")]
async fn google_login(oauth2: OAuth2<Google>, cookies: &CookieJar<'_>) -> Redirect {
    oauth2.get_redirect(cookies, &["profile"]).unwrap()
}

#[get("/auth/google")]
async fn google_callback(mut conn: Connection<Logs>, token: TokenResponse<Google>, cookies: &CookieJar<'_>) -> Redirect {
    let to = token.as_value().get("id_token").expect("invalid ID token");
    let ts = to.as_str().expect("invalid ID token").to_string();

    cookies.add_private(
        Cookie::build("token", ts.clone())
            .same_site(SameSite::Lax)
            .finish()
    );

    let user_id = jwks_verify_token(ts.clone()).await.expect("Expected valid user").id;
    sqlx::query("INSERT INTO public.users (uid, role) VALUES ($1, $2) ON CONFLICT DO NOTHING;").bind(user_id).bind(0).execute(&mut *conn).await.expect("Failed to add user");
    Redirect::to("/")
}

/*#[post("/events", format = "json", data = "<data>")]
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
}*/

#[post("/venues", data = "<data>")]
async fn add_venue(data: rocket::form::Form<VenueSubmission<>>, mut conn: Connection<Logs>, cookies: &CookieJar<'_>) -> Option<String> {
    match get_current_user(cookies).await {
        Some(c) => {
            let a = sqlx::query("INSERT INTO public.venues(
                name, description, capacity, address, thumbnail_url, owner)
                VALUES ($1, $2, $3, $4, $5)")
            .bind(&data.name)
            .bind(&data.description)
            .bind(&data.capacity)
            .bind(&data.address)
            .bind(&data.thumbnail_url)
            .bind(&c.id)
            .execute(&mut *conn).await.ok()?;
            Some(format!("Hello!"))
        },
        None => None
    }
}

async fn get_featured_events(mut conn: &mut PoolConnection<Postgres>, limit: i32) -> Option<Vec<Event>> {
    let mut criteria = EventFilterCriteria::new();
    criteria.limit = Some(1); 
    criteria.exec_query(&mut *conn).await.ok()
}

#[get("/events/<id>")]
async fn get_event(mut conn: Connection<Logs>, id: i64, cookies: &CookieJar<'_>) -> Option<Template> {
    let mut ctx = Context::new();

    match get_current_user(cookies).await {
        Some(c) => ctx.insert("user", &c),
        None => ctx.insert("user", &false),
    };
    
    let mut criteria = EventFilterCriteria::new();
    criteria.uid = Some(id); 
    let event = criteria.exec_query(&mut *conn).await.ok()?;
    if(event.len() == 0) { return None }
    ctx.insert("event", &event[0]);

    Some(Template::render("event", ctx.into_json()))
}

#[get("/venues/<id>")]
async fn get_venue(mut conn: Connection<Logs>, id: i64, cookies: &CookieJar<'_>) -> Option<Template> {
    let mut ctx = Context::new();

    match get_current_user(cookies).await {
        Some(c) => ctx.insert("user", &c),
        None => ctx.insert("user", &false),
    };
    
    let venue: Venue = sqlx::query("SELECT uid, name, description, capacity, address, thumbnail_url FROM venues WHERE uid = $1").bind(id)
        .map(|row: PgRow| Venue {
            uid: row.get("uid"),
            name: row.get("name"),
            description: row.get("description"),
            capacity: row.get("capacity"),
            address: row.get("address"),
            thumbnail_url: row.get("thumbnail_url"),
        })
        .fetch_one(&mut *conn).await.ok()?;
    ctx.insert("venue", &venue);

    let mut criteria = EventFilterCriteria::new();
    criteria.venue_id = Some(id); 
    let events = criteria.exec_query(&mut *conn).await.ok();

    match events {
        Some(e) => {
            ctx.insert("events", &e);
        }
        None => {
            ctx.insert("events", &false);
        }
    }

    Some(Template::render("venue", ctx.into_json()))
    
}

#[get("/")]
async fn index(mut conn: Connection<Logs>, cookies: &CookieJar<'_>) -> Option<Template> {
    let mut ctx = Context::new();

    match get_current_user(cookies).await {
        Some(c) => ctx.insert("user", &c),
        None => ctx.insert("user", &false),
    };

    let mut criteria = EventFilterCriteria::new();
    criteria.is_active = true; // UNIMPLEMENTED
    let events = criteria.exec_query(&mut *conn).await.ok();

    match events {
        Some(e) => {
            ctx.insert("events", &e);
        }
        None => {
            ctx.insert("events", &false);
        }
    }

    let mut criteria = VenueFilterCriteria::new();
    //criteria.limit = 5; // UNIMPLEMENTED
    let venues = criteria.exec_query(&mut *conn).await.ok();

    match venues {
        Some(e) => {
            ctx.insert("venues", &e);
        }
        None => {
            ctx.insert("venues", &false);
        }
    }

    let featured = get_featured_events(&mut *conn, 1).await;

    match featured {
        Some(e) => {
            ctx.insert("featured", &e);
        }
        None => {
            ctx.insert("featured", &false);
        }
    }

    Some(Template::render("index", ctx.into_json()))
}

#[get("/dashboard")]
async fn dashboard() -> Redirect {
    Redirect::to("/dashboard/venues")
}

#[get("/dashboard/venues")]
async fn dashboard_venues(mut conn: Connection<Logs>, cookies: &CookieJar<'_>) -> Option<Template> {
    let mut ctx = Context::new();
    let mut criteria = VenueFilterCriteria::new();

    match get_current_user(cookies).await {
        Some(c) => {
            ctx.insert("user", &c);
            criteria.owner = Some(c.id.clone());
        },
        None => {Redirect::to("/");},
    };
    print!("{:?}", criteria);

    let venues = criteria.exec_query(&mut *conn).await.ok(); 

    match venues {
        Some(e) => {
            ctx.insert("venues", &e);
        }
        None => {
            ctx.insert("venues", &false);
        }
    }

    Some(Template::render("dashboard_venues", ctx.into_json()))
}

#[get("/dashboard/events")]
async fn dashboard_events(mut conn: Connection<Logs>, cookies: &CookieJar<'_>) -> Option<Template> {
    let mut ctx = Context::new();
    
    match get_current_user(cookies).await {
        Some(c) => ctx.insert("user", &c),
        None => {Redirect::to("/");},
    };
    
    //let events: Vec<Event> = get_event_listings(conn).await?; 
    //ctx.insert("events", &events);

    Some(Template::render("dashboard_events", ctx.into_json()))
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .attach(Logs::init())
        .mount("/", routes![google_callback, google_login, index, dashboard_venues, dashboard_events, get_venue, get_event, /*add_event,*/ add_venue, dashboard])
        .mount("/assets", FileServer::from("./assets"))
        .attach(OAuth2::<Google>::fairing("google"))
        .attach(Template::fairing())
}