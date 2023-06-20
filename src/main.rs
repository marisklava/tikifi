#[macro_use] extern crate rocket;
extern crate chrono;

use rocket::{post, response::content, response, routes, form::{self, Form}, serde::{Deserialize, Serialize, json::*}};
use crate::rocket::form::validate::Len;
use rocket::http::{Cookie, CookieJar, SameSite, ContentType, Status, uri::Uri};
use rocket::response::{Responder};
use rocket::Request;
use rocket::request::{self, FromRequest};
use rocket::fs::FileServer;
use rocket::response::Redirect;
use rocket_db_pools::{sqlx::{self, FromRow, Row, postgres::*, query_builder::QueryBuilder, Execute, pool::PoolConnection}, Database, Connection};
use regex::Regex;

use chrono::{Local, DateTime, TimeZone, NaiveDate, NaiveDateTime, Utc};

use rocket_oauth2::{OAuth2, TokenResponse};
struct Google;

use rocket_dyn_templates::{Template, context, tera::Context};

use jwksclient2::{error::Error, jwt::Payload};
use jwksclient2::keyset::KeyStore;

use uuid::Uuid; 

use anyhow::{anyhow, Result};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("SerdeJson Error {source:?}")]
    SerdeJson {
        #[from] source: serde_json::Error,
    },
    #[error("Sqlx Error {source:?}")]
    Sqlx {
        #[from] source: rocket_db_pools::sqlx::Error,
    },
    #[error("Rocket_oauth Error {source:?}")]
    RocketOauth {
        #[from] source: rocket_oauth2::Error,
    },
    #[error("jwksclient2 Error {source:?}")]
    JwksClient {
        #[from] source: jwksclient2::error::Error,
    },
    #[error("Anyhow Error {source:?}")]
    Anyhow {
        #[from] source: anyhow::Error,
    },
    #[error("Std I/O Error {source:?}")]
    StdIo {
        #[from] source: std::io::Error,
    },
    #[error("Chrono parse Error")]
    ChronoParse {
        #[from] source: chrono::ParseError,
    },
    #[error("Chrono parse Error")]
    ResourceNotFound
    /*#[error("Png Encoding Error {source:?}")]
    PngEncoding {
        #[from] source: png::EncodingError,
    }*/
}

impl<'r, 'o: 'r> Responder<'r, 'o> for ApiError {
    fn respond_to(self, req: &'r Request<'_>) -> response::Result<'o> {
        println!{"Error: {:?}", self};
        match self {
            ApiError::ResourceNotFound => Status::NotFound.respond_to(req),
            ApiError::Sqlx { source: rocket_db_pools::sqlx::Error::RowNotFound } => Status::NotFound.respond_to(req),
            _ => Status::InternalServerError.respond_to(req)
        }
    }
}

#[catch(default)]
fn default_catcher(error: rocket::http::Status, request: &Request<'_>) {

}

//exclude these routes from the initial uri redirect
const EXCLUDED_ROUTES: [&'static str; 3] = ["/cart/view", "/ticket/buy", "/test/route"];

#[catch(403)]
fn forbidden_catcher(error: rocket::http::Status, request: &Request<'_>) -> Redirect {
    if(!EXCLUDED_ROUTES.contains(&request.uri().to_string().as_str())) {
        request.cookies().add(
            Cookie::build("initial_uri", request.uri().to_string())
                .same_site(SameSite::Lax)
                .finish()
        );
    }
    Redirect::to("/login/google")
}

#[derive(Database)]
#[database("tikifi")]
struct Logs(sqlx::PgPool);

#[derive(Debug, Deserialize, Serialize, Clone, sqlx::FromRow)]
#[serde(crate = "rocket::serde")]
pub struct Like { 
    user: String,
    listing: String,
}

impl Like {
    async fn add(mut conn: &mut PoolConnection<Postgres>, listing: String, user: UserInfo) -> Result<(), ApiError> {
        sqlx::query("INSERT IGNORE INTO public.likes(user, listing) VALUES ($1, $2);")
        .bind(listing)
        .bind(user.id)
        .execute(&mut *conn).await?;
        Ok(())
    }
    async fn remove(mut conn: &mut PoolConnection<Postgres>, listing: String, user: UserInfo) -> Result<(), ApiError> {
        sqlx::query("DELETE FROM public.likes WHERE user=$1 AND listing=$2;")
        .bind(listing)
        .bind(user.id)
        .execute(&mut *conn).await?;
        Ok(())
    }
    async fn check(mut conn: &mut PoolConnection<Postgres>, listing: String, user: UserInfo) -> Result<bool, ApiError> {
        sqlx::query("DELETE FROM public.likes WHERE user=$1 AND listing=$2;")
        .bind(listing)
        .bind(user.id)
        .execute(&mut *conn).await?;
        Ok(true)
    }
}

#[derive(Debug, Clone, Default)]
pub struct TicketFilterCriteria { 
    uid: Option<String>,
    used: Option<bool>,
    venue: Option<String>,
    venue_name: Option<String>,
    event: Option<String>,
    event_name: Option<String>,
    event_date: Option<DateTime<Utc>>,
    purchaser: Option<String>,
}

impl TicketFilterCriteria {
    fn new() -> TicketFilterCriteria {
        TicketFilterCriteria { ..Default::default() }
    }

    async fn exec_query(self, mut conn: &mut PoolConnection<Postgres>) -> Result<Vec<Ticket>, ApiError> {
        let mut q = QueryBuilder::new("SELECT ti.uid AS ticket_id, ti.used, ti.venue, ti.event, ti.purchaser, ven.name AS venue_name, ev.name as event_name, ev.event_date FROM public.tickets AS ti JOIN venues AS ven ON ti.venue = ven.uid JOIN events AS ev ON ti.event = ev.uid");
        if self.purchaser.is_some() { q.push(" AND ti.purchaser = "); q.push_bind(self.purchaser.unwrap());};

        let result = q.build()
        .map(|row: PgRow| Ticket {
            uid: row.get("ticket_id"),
            used: row.get("used"),
            venue: row.get("venue"),
            venue_name: row.get("venue_name"), 
            event: row.get("event"),
            event_name: row.get("event_name"),
            event_date: row.get("event_date"),
            purchaser: row.get("purchaser"),
        }).fetch_all(&mut *conn).await?;
        Ok(result)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, sqlx::FromRow)]
#[serde(crate = "rocket::serde")]
pub struct Ticket { // Ticket struct for interfacing with the database and generating PDF tickets
    uid: String,
    used: bool,
    venue: String,
    venue_name: String,
    event: String,
    event_name: String,
    event_date: DateTime<Utc>,
    purchaser: String,
}

impl Ticket {
    async fn create(mut conn: &mut PoolConnection<Postgres>, event_id: String, user_id: String) -> Result<(), ApiError> {
        let ticket_id: String = sqlx::query("INSERT INTO public.tickets(
            used, event, venue, purchaser)
            VALUES (false, $1, (SELECT ev.venue FROM events AS ev WHERE ev.uid=$2), $3) RETURNING uid")
        .bind(&event_id)
        .bind(&event_id)
        .bind(&user_id)
        .map(|row: PgRow| row.get("uid"))
        .fetch_one(&mut *conn).await?;
        Ok(())
    }
    async fn get_info(mut conn: &mut PoolConnection<Postgres>, ticket_id: String, user_id: String) -> Result<Ticket, ApiError> {
        let mut query = QueryBuilder::new("SELECT ti.uid AS ticket_id, ti.used, ti.venue, ti.event, ti.purchaser, ven.name AS venue_name, ev.name as event_name, ev.event_date FROM public.tickets AS ti JOIN venues AS ven ON ti.venue = ven.uid JOIN events AS ev ON ti.event = ev.uid");
        query.push(" WHERE ti.uid = "); 
        query.push_bind(ticket_id);
        query.push(" AND purchaser = "); 
        query.push_bind(user_id);
        let result = query.build()
        .map(|row: PgRow| Ticket {
            uid: row.get("ticket_id"),
            used: row.get("used"),
            venue: row.get("venue"),
            venue_name: row.get("venue_name"), 
            event: row.get("event"),
            event_name: row.get("event_name"),
            event_date: row.get("event_date"),
            purchaser: row.get("purchaser"),
        }).fetch_one(&mut *conn).await?;
        Ok(result)
    }
    async fn check_ticket(mut conn: &mut PoolConnection<Postgres>, ticket_id: String, user_id: String, event_id: String,) -> Result<bool, ApiError> { // Going to add a sort of "doors open" datetime functionality later on
        let valid: bool = sqlx::query("
            WITH update_proc AS (UPDATE tickets SET used = true 
            WHERE \"uid\" = $1 
            AND EXISTS (SELECT FROM events 
            WHERE event = $2
            AND author = $3
            AND used = false)
            RETURNING used)
            SELECT EXISTS(SELECT * FROM update_proc) AS permitted
        ")
        .bind(&ticket_id)
        .bind(&event_id)
        .bind(&user_id)
        .map(|row: PgRow| row.get("permitted"))
        .fetch_one(&mut *conn).await?;
        Ok(valid)

        /*
    
SELECT case
		when (EXISTS (SELECT FROM tickets WHERE 
				uid = 'uid' 
				AND EXISTS (SELECT FROM events 
						WHERE event = 'event'
						AND author = 'author'
						AND used = false)))
		then true
		else false
	END AS permitted

        */

/*



 */

    }//UPDATE tickets SET used=true WHERE uid = $1
}

#[derive(FromForm)]
pub struct EventSubmission<'r> {
    name: String,
    description: String,
    event_date: String,
    //is_draft: bool,
    venue: String,
    #[field(validate = validate_image())]
    thumbnail: Option<rocket::fs::TempFile<'r>>,
    price: f32,
}

#[derive(Debug, Deserialize, Serialize, Clone, FromRow)]
#[serde(crate = "rocket::serde")]
pub struct Event {
    uid: String,
    name: String,
    description: String,
    event_date: DateTime<Utc>,
    venue_id: String,
    venue_name: String,
    thumbnail_url: String,
    price: f32,
}

#[derive(Default, Debug)]
struct EventFilterCriteria {
    uid: Option<String>,
    uids: Option<Vec<String>>,
    author: Option<String>,
    text: Option<String>,
    venue_name: Option<String>, //UNIMPLEMENTED
    event_date: Option<NaiveDate>,
    start_date: Option<NaiveDate>,
    end_date: Option<NaiveDate>,
    start_price: Option<f32>,
    end_price: Option<f32>,
    venue_id: Option<String>,
    is_draft: bool, //UNIMPLEMENTED
    is_active: bool, //UNIMPLEMENTED
    limit: Option<i32>,
    price: Option<f32>,
}

impl EventFilterCriteria {
    fn new() -> EventFilterCriteria {
        EventFilterCriteria { ..Default::default() }
    }

    async fn exec_query(self, mut conn: &mut PoolConnection<Postgres>) -> Result<Vec<Event>, ApiError> {
        fn sep(c: i32) -> String {
            if(c==1) { return " WHERE ".to_string() }
            else { return " AND ".to_string() }
        }
        
        let mut q = QueryBuilder::new("SELECT ev.uid, ev.name, ev.description, ev.event_date, ev.price, ev.thumbnail_url, ev.venue AS venue_id, ven.name AS venue_name FROM events AS ev JOIN venues AS ven ON ev.venue = ven.uid");
        
        if(self.uid.is_some()) { q.push(" AND ev.uid = "); q.push_bind(self.uid.unwrap());};

        if(self.uids.is_some()) { 
            q.push(" AND ev.uid IN ("); 
            
            let uids = self.uids.unwrap();
            for i in 0..uids.len() {
                q.push_bind(uids[i].clone());
                println!("{} {}", uids.len(), i);
                if(i != uids.len()-1) { q.push(", "); } else { q.push(" "); };
            }
 
            q.push(") ");
        };

        if(self.venue_id.is_some()) { q.push(" AND ev.venue = "); q.push_bind(self.venue_id.unwrap());};
        if(self.text.is_some()) { q.push(" AND lower(ev.name) LIKE '%' || "); q.push_bind(self.text.unwrap().to_lowercase()); q.push(" || '%'");};
        if(self.author.is_some()) { q.push(" AND ev.author = "); q.push_bind(self.author.unwrap());};
        if(self.event_date.is_some()) { q.push(" AND (ev.event_date - "); q.push_bind(self.event_date.unwrap()); q.push(") < interval '2 days'");};
        
        if(self.start_date.is_some()) { q.push(" AND (ev.event_date > "); q.push_bind(self.start_date.unwrap()); q.push(")");};
        if(self.end_date.is_some()) { q.push(" AND (ev.event_date < "); q.push_bind(self.end_date.unwrap()); q.push(")");};

        if(self.start_price.is_some()) { q.push(" AND ev.price > "); q.push_bind(self.start_price.unwrap());};
        if(self.end_price.is_some()) { q.push(" AND ev.price < "); q.push_bind(self.end_price.unwrap());};

        if(self.price.is_some()) { q.push(" AND ev.price < "); q.push_bind(self.price.unwrap());};
        if(self.limit.is_some()) { q.push(" LIMIT "); q.push_bind(self.limit.unwrap());};


        let a = q.build();
        println!("{:?}",a.sql());
        //println!("{:?}",self.event_date.unwrap());

        let result = a.map(|row: PgRow| Event {
            uid: row.get("uid"),
            name: row.get("name"),
            description: row.get("description"),
            event_date: row.get("event_date"),
            venue_id: row.get("venue_id"),
            venue_name: row.get("venue_name"),
            thumbnail_url: row.get("thumbnail_url"),
            price: row.get("price"),
        }).fetch_all(&mut *conn).await?;
        
        Ok(result)
    }
    async fn get_names(self, mut conn: &mut PoolConnection<Postgres>) -> Result<Vec<ListingName>, ApiError> {
        let mut q = QueryBuilder::new("SELECT ev.uid, ev.name FROM events AS ev WHERE true");
        
        if(self.author.is_some()) { q.push(" AND \"author\" = "); q.push_bind(self.author.unwrap());};

        let result = q.build().map(|row: PgRow| ListingName {
            uid: row.get("uid"),
            name: row.get("name"),
        }).fetch_all(&mut *conn).await?;

        Ok(result)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, FromRow)]
#[serde(crate = "rocket::serde")]
pub struct Venue {
    uid: String,
    name: String,
    description: String,
    capacity: i64,
    address: String,
    thumbnail_url: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(crate = "rocket::serde")]
pub struct ListingName {
    uid: String,
    name: String,
}

#[derive(FromForm)]
pub struct VenueSubmission<'r> {
    name: String,
    description: String,
    //capacity: i64,
    address: String,
    //thumbnail_url: String,
    #[field(validate = validate_image())] //ContentType::new("image", "*")
    thumbnail: Option<rocket::fs::TempFile<'r>>,
}

//thumbnail: rocket::fs::TempFile<'r>,
fn validate_image<'v>(file: &Option<rocket::fs::TempFile<'_>>) -> form::Result<'v, ()> {
    if <std::option::Option<rocket::fs::TempFile<'_>> as Len<u64>>::len(file) == 0 {
        return Ok(())
    }

    let tfile = match file {
        Some(f) => f,
        None => return Ok(()),
    };

    if(tfile.content_type().is_none()) { return Ok(()) };
    let ctt = tfile.content_type().unwrap();
    match ctt == &ContentType::JPEG || ctt == &ContentType::PNG || ctt == &ContentType::WEBP
    {
        true => Ok(()),
        false => Err(form::Errors::from(form::Error::validation(
            "Unsupported image",
        ))),
    }

}

#[derive(Default, Debug)]
struct VenueFilterCriteria {
    uid: Option<String>,
    owner: Option<String>,
    text: Option<String>,
    name: Option<String>,
    description: Option<String>,
    capacity: Option<i64>,
    address: Option<String>,
}

impl VenueFilterCriteria {
    fn new() -> VenueFilterCriteria {
        VenueFilterCriteria { ..Default::default() }
    }
    async fn exec_query(self, mut conn: &mut PoolConnection<Postgres>) -> Result<Vec<Venue>, ApiError> {
        fn sep(c: i32) -> String {
            if(c==1) { return " WHERE ".to_string() }
            else { return " AND ".to_string() }
        }

        let mut q = QueryBuilder::new("SELECT ven.uid, ven.name, ven.description, ven.capacity, ven.address, ven.thumbnail_url FROM venues AS ven WHERE true");
        
        if(self.uid.is_some()) { q.push(" AND uid = "); q.push_bind(self.uid.unwrap());};
        if(self.owner.is_some()) { q.push(" AND \"owner\" = "); q.push_bind(self.owner.unwrap());};
        if(self.text.is_some()) { q.push(" AND lower(ven.name) LIKE '%' || "); q.push_bind(self.text.unwrap().to_lowercase()); q.push(" || '%'");};

        let result = q.build().map(|row: PgRow| Venue {
            uid: row.get("uid"),
            name: row.get("name"),
            description: row.get("description"),
            capacity: row.get("capacity"),
            address: row.get("address"),
            thumbnail_url: row.get("thumbnail_url"),
        }).fetch_all(&mut *conn).await?;

        Ok(result)
    }

    async fn get_names(self, mut conn: &mut PoolConnection<Postgres>) -> Result<Vec<ListingName>, ApiError> {
        let mut q = QueryBuilder::new("SELECT ven.uid, ven.name FROM venues AS ven WHERE true");
        
        if(self.owner.is_some()) { q.push(" AND \"owner\" = "); q.push_bind(self.owner.unwrap());};

        let result = q.build().map(|row: PgRow| ListingName {
            uid: row.get("uid"),
            name: row.get("name"),
        }).fetch_all(&mut *conn).await?;

        Ok(result)
    }
}

#[derive(Serialize, Debug)]
#[serde(crate = "rocket::serde")]
pub struct UserInfo {
    id: String,
    avatar: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for UserInfo {
    type Error = ApiError;

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        match req.cookies().get_private("token") { 
            Some(te) => {
                let jkws_url = "https://www.googleapis.com/oauth2/v3/certs";
                let key_set = KeyStore::new_from(jkws_url.to_owned()).await.unwrap();
            
                match key_set.verify(&te.value().to_string().clone()) {
                    Ok(jwt) => {
                        let payload = jwt.payload();
                        return rocket::outcome::Outcome::Success(
                            UserInfo {
                                id: payload.get_str("sub").expect("Expected sub value").to_owned(),
                                avatar: payload.get_str("picture").expect("Expected picture value").to_owned(),
                            }
                        )
                    }
                    Err(e) => return rocket::outcome::Outcome::Failure((rocket::http::Status::InternalServerError,ApiError::JwksClient { source: e }))
                };
            },
            None => return rocket::outcome::Outcome::Failure((rocket::http::Status::Forbidden,ApiError::Anyhow { source: anyhow!("Authorization failure") })),
        }
    }
}

/*
async fn check_event_author(mut conn: &mut PoolConnection<Postgres>, user_id: i64, venue_id: i64) -> bool {
    let a = sqlx::query("SELECT exists(SELECT FROM events WHERE author = $1 AND uid = $2)").bind(user_id).bind(venue_id)
    .fetch_one(&mut *conn).await.unwrap();
    a.get("exists")
}

async fn check_venue_author(mut conn: &mut PoolConnection<Postgres>, user_id: i64, venue_id: i64) -> bool {
    let a = sqlx::query("SELECT exists(SELECT FROM venues WHERE owner = $1 AND uid = $2)").bind(user_id).bind(venue_id)
    .fetch_one(&mut *conn).await.unwrap();
    a.get("exists")
}
*/

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

#[get("/logout")]
async fn google_logout(oauth2: OAuth2<Google>, cookies: &CookieJar<'_>) -> Result<Redirect, ApiError> {
    cookies.remove(Cookie::named("token"));
    Ok(Redirect::to("/"))
}

#[get("/login/google")]
async fn google_login(oauth2: OAuth2<Google>, cookies: &CookieJar<'_>) -> Result<Redirect, ApiError> {
    Ok(oauth2.get_redirect(cookies, &["profile"])?)
}

#[get("/auth/google")]
async fn google_callback(mut conn: Connection<Logs>, token: TokenResponse<Google>, cookies: &CookieJar<'_>) -> Result<Redirect, ApiError> { // Needs error handling
    let initial_uri = cookies.get("initial_uri");
    let to = token.as_value().get("id_token").expect("invalid ID token");
    let ts = to.as_str().expect("invalid ID token").to_string();

    cookies.add_private(
        Cookie::build("token", ts.clone())
            .same_site(SameSite::Lax)
            .finish()
    );

    let user_id = jwks_verify_token(ts.clone()).await.expect("Expected valid user").id;
    sqlx::query("INSERT INTO public.users (uid, role) VALUES ($1, $2) ON CONFLICT DO NOTHING;").bind(user_id).bind(0).execute(&mut *conn).await?;
    match initial_uri {
        Some(uri) => Ok(Redirect::to(uri.value().to_string())),
        None => Ok(Redirect::to("/"))
    }
}

async fn persist_thumb(thumbnail: &mut rocket::fs::TempFile<'_>) -> Result<String, ApiError> {
    let thumb_dir = format!("images/{}", &Uuid::new_v4().to_string());
    thumbnail.persist_to(&thumb_dir).await?; //todo: upload to cdn
    Ok(format!("/{}",thumb_dir))
}

#[post("/events", data = "<data>")] //Insecure
async fn add_event(mut data: rocket::form::Form<EventSubmission<'_>>, mut conn: Connection<Logs>, cookies: &CookieJar<'_>, user: UserInfo) -> Result<Redirect, ApiError> {

    let a = sqlx::query("INSERT INTO public.events(
        name, description, event_date, venue, author, price)
        VALUES ($1, $2, $3, $4, $5, $6) RETURNING uid")
    .bind(&data.name)
    .bind(&data.description)
    .bind(&NaiveDate::parse_from_str(&data.event_date,"%Y-%m-%d")?)
    .bind(&data.venue)
    .bind(&user.id)
    .bind(&data.price)
    .fetch_one(&mut *conn).await?;

    if(<std::option::Option<rocket::fs::TempFile<'_>> as Len<u64>>::len(&data.thumbnail) > 0) { 
        
        let mut q = QueryBuilder::new("UPDATE events SET thumbnail_url = ");

        let mut thumb = data.thumbnail.as_mut().unwrap();
        let thumb_dir = persist_thumb(&mut thumb).await?; 
        q.push_bind(thumb_dir);

        q.push(" WHERE uid = ");
        let uid: String = a.get("uid");
        q.push_bind(uid);

        q.push(" AND author = ");
        q.push_bind(user.id);

        q.build().execute(&mut *conn).await?;    
    };

    Ok(Redirect::to("/dashboard/events")) // thumbnail_url
}

/*
            let thumb_dir = format!("images/{}", &Uuid::new_v4().to_string());
            data.thumbnail.persist_to(&thumb_dir).await.unwrap(); //todo: upload to cdn

            let mut q = QueryBuilder::new("INSERT INTO public.events (SELECT ");

            q.push_bind(&data.name); q.push(" AS name"); q.push(", ");
            q.push_bind(&data.description); q.push(" AS description"); q.push(", ");
            q.push_bind(NaiveDate::parse_from_str(&data.event_date,"%Y-%m-%d").unwrap()); q.push(" AS event_date"); q.push(", ");
            q.push_bind(&data.venue); q.push(" AS venue"); q.push(", ");

            q.push_bind(format!("{}",&thumb_dir)); q.push(" AS thumbnail_url"); q.push(", ");

            q.push_bind(&data.price); q.push(" AS price)"); 

            q.build().execute(&mut *conn).await.ok()?;
            Some(Redirect::to("/dashboard/events"))
*/

#[post("/events/<id>", data = "<data>")]
async fn edit_event(mut data: rocket::form::Form<EventSubmission<'_>>, id: String, mut conn: Connection<Logs>, user: UserInfo) -> Result<Redirect, ApiError> {

    let mut q = QueryBuilder::new("UPDATE events SET ");

    q.push("name="); q.push_bind(data.name.clone()); q.push(", ");
    q.push("description="); q.push_bind(data.description.clone()); q.push(", ");
    q.push("event_date="); q.push_bind(NaiveDate::parse_from_str(&data.event_date.clone(),"%Y-%m-%d").unwrap()); q.push(", ");
    q.push("venue="); q.push_bind(data.venue.clone()); q.push(", ");

    if(<std::option::Option<rocket::fs::TempFile<'_>> as Len<u64>>::len(&data.thumbnail) > 0) { 
        let mut thumb = data.thumbnail.as_mut().unwrap();
        let thumb_dir = persist_thumb(&mut thumb).await.unwrap();
        q.push("thumbnail_url="); q.push_bind(format!("{}",&thumb_dir)); q.push(", "); 
    };

    q.push("price="); q.push_bind(&data.price);
    q.push("WHERE uid ="); q.push_bind(id);
    q.push("AND author ="); q.push_bind(&user.id);

    q.build().execute(&mut *conn).await?;
    Ok(Redirect::to("/dashboard/events"))
}

#[post("/venues", data = "<data>")]
async fn add_listing(mut data: rocket::form::Form<VenueSubmission<'_>>, mut conn: Connection<Logs>, user: UserInfo) -> Result<Redirect, ApiError> {
    
    let a = sqlx::query("INSERT INTO public.venues(
        name, description, capacity, address, owner)
        VALUES ($1, $2, $3, $4, $5) RETURNING uid")
    .bind(&data.name)
    .bind(&data.description)
    .bind(&500)
    .bind(&data.address)
    .bind(&user.id)
    .fetch_one(&mut *conn).await?;

    if(<std::option::Option<rocket::fs::TempFile<'_>> as Len<u64>>::len(&data.thumbnail) > 0) { 

        let mut q = QueryBuilder::new("UPDATE venues SET thumbnail_url = ");
        
        let mut thumb = data.thumbnail.as_mut().unwrap();
        let thumb_dir = persist_thumb(&mut thumb).await?; 
        q.push_bind(thumb_dir);

        q.push(" WHERE uid = ");
        let uid: String = a.get("uid");
        q.push_bind(uid);

        q.push(" AND \"owner\" = ");
        q.push_bind(user.id);

        q.build().execute(&mut *conn).await?;    

    };

    Ok(Redirect::to("/dashboard/venues"))
}

#[post("/venues/<id>", data = "<data>")]
async fn edit_venue(mut data: rocket::form::Form<VenueSubmission<'_>>, id: String, mut conn: Connection<Logs>, user: UserInfo) -> Result<Redirect, ApiError> {
    let lid = id.clone();
    let a = sqlx::query("UPDATE venues SET name=$1, description=$2, capacity=$3, address=$4 WHERE uid=$5 AND \"owner\"=$6")
    .bind(&data.name)
    .bind(&data.description)
    .bind(&500)
    .bind(&data.address)
    .bind(&lid)
    .bind(&user.id);
    println!("{:?}",a.sql());

    a.execute(&mut *conn).await?;

    if(<std::option::Option<rocket::fs::TempFile<'_>> as Len<u64>>::len(&data.thumbnail) > 0) { 

        let mut q = QueryBuilder::new("UPDATE venues SET thumbnail_url = ");
        
        let mut thumb = data.thumbnail.as_mut().unwrap();
        let thumb_dir: String = persist_thumb(&mut thumb).await?; 
        q.push_bind(thumb_dir);

        q.push(" WHERE uid = ");
        let uid: String = id.clone();
        q.push_bind(uid);

        q.push(" AND \"owner\" = ");
        q.push_bind(user.id);

        let b = q.build();
        println!("{:?}",b.sql());

        b.execute(&mut *conn).await?;    
    };

    Ok(Redirect::to("/dashboard/venues"))
}

#[get("/venues/<id>/delete")]
async fn delete_venue(id: String, mut conn: Connection<Logs>, cookies: &CookieJar<'_>, user: UserInfo) -> Result<Redirect, ApiError> {
    let a = sqlx::query("DELETE FROM venues WHERE uid=$1 AND \"owner\"=$2")
        .bind(id)
        .bind(&user.id)
        .execute(&mut *conn).await?;
    Ok(Redirect::to("/dashboard/venues"))
}

#[get("/events/<id>/delete")]
async fn delete_event(id: String, mut conn: Connection<Logs>, cookies: &CookieJar<'_>, user: UserInfo) -> Result<Redirect, ApiError> {
    let a = sqlx::query("DELETE FROM events WHERE uid=$1 AND author=$2")
        .bind(id)
        .bind(&user.id)
        .execute(&mut *conn).await?;
    Ok(Redirect::to("/dashboard/events"))
}

async fn get_featured_events(mut conn: &mut PoolConnection<Postgres>, limit: i32) -> Result<Vec<Event>, ApiError> {
    let mut criteria = EventFilterCriteria::new();
    criteria.limit = Some(limit); 
    Ok(criteria.exec_query(&mut *conn).await?)
}

async fn render_listings(events: Vec<Event>, venues: Vec<Venue>) -> Option<Template> {
    let mut ctx = Context::new();
    if events.len() == 0 && venues.len() == 0 { return None }
    if events.len() > 0 { ctx.insert("events", &events); }
    if venues.len() > 0 { ctx.insert("venues", &venues); }
    Some(Template::render("results", ctx.into_json()))
}

#[get("/search?<query>&<date>&<start_date>&<end_date>&<price>&<start_price>&<end_price>")]
async fn search_listings(mut conn: Connection<Logs>, user: Option<UserInfo>, query: Option<String>, date: Option<String>, start_date: Option<String>, end_date: Option<String>, price: Option<f32>, start_price: Option<f32>, end_price: Option<f32>) -> Option<Template> {
    //if(date.is_some()) { println!("Date: {:?}", NaiveDate::parse_from_str(&date.unwrap(),"%Y-%m-%d").ok()?) };
    //if(price.is_some()) { println!("Price: {:?}", price.unwrap()) };

    let mut ctx = Context::new();

    match user {
        Some(c) => ctx.insert("user", &c),
        None => ctx.insert("user", &false),
    };
    
    let mut ecriteria = EventFilterCriteria::new();
    ecriteria.text = query.clone(); 
    if(start_date.is_some()) { ecriteria.start_date = Some(NaiveDate::parse_from_str(&start_date.clone().unwrap(),"%Y-%m-%d").unwrap()) };
    if(end_date.is_some()) { ecriteria.end_date = Some(NaiveDate::parse_from_str(&end_date.clone().unwrap(),"%Y-%m-%d").unwrap()) };

    if(start_price.is_some()) { ecriteria.start_price = start_price; };
    if(end_price.is_some()) { ecriteria.end_price = end_price; };
    
    let mut vcriteria: VenueFilterCriteria = VenueFilterCriteria::new();
    vcriteria.text = query; 
    
    let events = ecriteria.exec_query(&mut *conn).await.ok()?;
    let mut venues: Vec<Venue> = vec![];
    if start_date.is_none() && end_date.is_none() && start_price.is_none() && end_price.is_none() { venues = vcriteria.exec_query(&mut *conn).await.ok()? };

    render_listings(events,venues).await
}

#[get("/events/<id>")] // insecure
async fn get_event(mut conn: Connection<Logs>, id: String, user: Option<UserInfo>, cur_uri: &rocket::http::uri::Origin<'_>) -> Result<Template, ApiError> {
    let mut ctx = Context::new();
    ctx.insert("path", &cur_uri.path().as_str());

    match user {
        Some(c) => ctx.insert("user", &c),
        None => ctx.insert("user", &false),
    };
    
    let mut criteria = EventFilterCriteria::new();
    criteria.uid = Some(id); 
    let event = criteria.exec_query(&mut *conn).await?;
    if event.len() == 0 { return Err(ApiError::ResourceNotFound) }
    ctx.insert("event", &event[0]);

    Ok(Template::render("event", ctx.into_json()))
}

#[get("/events/<id>/mini_listing")] // insecure
async fn get_event_mini_listing(mut conn: Connection<Logs>, id: String, user: Option<UserInfo>, cur_uri: &rocket::http::uri::Origin<'_>) -> Result<Template, ApiError> {
    let regex = Regex::new(r"(?m)^[0-9A-Za-z\-]+(,[0-9A-Za-z\-]+)*$").unwrap();

    let mut ctx = Context::new();
    ctx.insert("path", &cur_uri.path().as_str());

    match user {
        Some(c) => ctx.insert("user", &c),
        None => ctx.insert("user", &false),
    };
    
    let mut criteria = EventFilterCriteria::new();
    if(regex.is_match(&id)) {
        criteria.uids = Some(id.clone().split(",").map(String::from).collect::<Vec<String>>());
    } else {
        criteria.uid = Some(id); 
    }

    let events = criteria.exec_query(&mut *conn).await?;
    if events.len() == 0 { return Err(ApiError::ResourceNotFound) }
    ctx.insert("events", &events);

    Ok(Template::render("mini_listing", ctx.into_json()))

}

#[get("/venues/<id>")]
async fn get_venue(mut conn: Connection<Logs>, id: String, user: Option<UserInfo>, cur_uri: &rocket::http::uri::Origin<'_>) -> Result<Template, ApiError> {
    let mut ctx = Context::new();
    ctx.insert("path", &cur_uri.path().as_str());

    match user {
        Some(c) => ctx.insert("user", &c),
        None => ctx.insert("user", &false),
    };
    
    let venue: Venue = sqlx::query("SELECT uid, name, description, capacity, address, thumbnail_url FROM venues WHERE uid = $1").bind(id.clone())
        .map(|row: PgRow| Venue {
            uid: row.get("uid"),
            name: row.get("name"),
            description: row.get("description"),
            capacity: row.get("capacity"),
            address: row.get("address"),
            thumbnail_url: row.get("thumbnail_url"),
        })
        .fetch_one(&mut *conn).await?;
    ctx.insert("venue", &venue);

    let mut criteria = EventFilterCriteria::new();
    criteria.venue_id = Some(id); 
    let events = criteria.exec_query(&mut *conn).await?;

    match events.len() > 0 {
        true => {
            ctx.insert("events", &events);
        }
        false => {
            ctx.insert("events", &false);
        }
    }

    Ok(Template::render("venue", ctx.into_json()))
    
}

#[get("/")]
async fn index(mut conn: Connection<Logs>, cookies: &CookieJar<'_>, user: Option<UserInfo>, cur_uri: &rocket::http::uri::Origin<'_>) -> Result<Template, ApiError> {
    let mut ctx = Context::new();
    ctx.insert("path", &cur_uri.path().as_str());

    match user {
        Some(c) => ctx.insert("user", &c),
        None => ctx.insert("user", &false),
    };

    let mut criteria = EventFilterCriteria::new();
    criteria.is_active = true; // UNIMPLEMENTED
    let events = criteria.exec_query(&mut *conn).await?;

    match events.len() > 0 {
        true => {
            ctx.insert("events", &events);
        }
        false => {
            ctx.insert("events", &false);
        }
    }

    let mut criteria = VenueFilterCriteria::new();
    //criteria.limit = 5; // UNIMPLEMENTED
    let venues = criteria.exec_query(&mut *conn).await?;

    match venues.len() > 0 {
        true => {
            ctx.insert("venues", &venues);
        }
        false => {
            ctx.insert("venues", &false);
        }
    }

    let featured = get_featured_events(&mut *conn, 1).await?;

    match featured.len() > 0 {
        true => {
            ctx.insert("featured", &featured);
        }
        false => {
            ctx.insert("featured", &false);
        }
    }

    Ok(Template::render("index", ctx.into_json()))
}

#[get("/dashboard")]
async fn dashboard() -> Redirect {
    Redirect::to("/dashboard/venues")
}

#[get("/dashboard/venues")]
async fn dashboard_venues(mut conn: Connection<Logs>, user: UserInfo, cur_uri: &rocket::http::uri::Origin<'_>) -> Result<Template, ApiError> {
    let mut ctx = Context::new();
    ctx.insert("path", &cur_uri.path().as_str());
    ctx.insert("user", &user);

    let mut criteria = VenueFilterCriteria::new();
    criteria.owner = Some(user.id.clone());

    let venues = criteria.exec_query(&mut *conn).await.ok(); 

    match venues {
        Some(e) => {
            ctx.insert("venues", &e);
        }
        None => {
            ctx.insert("venues", &false);
        }
    }

    Ok(Template::render("dashboard_listings", ctx.into_json()))
}

#[get("/dashboard/tickets")]
async fn dashboard_tickets(mut conn: Connection<Logs>, user: UserInfo, cur_uri: &rocket::http::uri::Origin<'_>) -> Result<Template, ApiError> {
    let mut ctx = Context::new();
    ctx.insert("path", &cur_uri.path().as_str());
    ctx.insert("user", &user);

    let mut criteria = TicketFilterCriteria::new();
    criteria.purchaser = Some(user.id.clone());

    let tickets = criteria.exec_query(&mut *conn).await.ok(); 

    match tickets {
        Some(e) => {
            ctx.insert("tickets", &e);
        }
        None => {
            ctx.insert("tickets", &false);
        }
    }

    Ok(Template::render("dashboard_tickets", ctx.into_json()))
}

#[get("/dashboard/events")] // arguably insecure
async fn dashboard_events(mut conn: Connection<Logs>, user: UserInfo, cur_uri: &rocket::http::uri::Origin<'_>) -> Option<Template> {
    let mut ctx = Context::new();
    ctx.insert("path", &cur_uri.path().as_str());
    ctx.insert("user", &user);

    let mut criteria = EventFilterCriteria::new();
    criteria.author = Some(user.id.clone());
    let events: Option<Vec<Event>> = criteria.exec_query(&mut *conn).await.ok(); 

    let mut dropdown_criteria = VenueFilterCriteria::new();
    dropdown_criteria.owner = Some(user.id.clone());
    let venue_names: Option<Vec<ListingName>> = dropdown_criteria.get_names(&mut *conn).await.ok(); 

    match events {
        Some(e) => {
            ctx.insert("events", &e);
        }
        None => {
            ctx.insert("events", &false);
        }
    }

    match venue_names {
        Some(e) => {
            ctx.insert("venue_names", &e);
        }
        None => {
            ctx.insert("venue_names", &false);
        }
    }

    Some(Template::render("dashboard_listings", ctx.into_json()))
}

use fast_qr::convert::{image::ImageBuilder, Builder, Shape};
use fast_qr::qr::QRBuilder;

use image::{ColorType, GenericImageView, ImageFormat};
use miniz_oxide::deflate::{compress_to_vec_zlib, CompressionLevel};
use pdf_writer::{Content, Filter, Finish, Name, PdfWriter, Rect, Ref, Str};

async fn generate_ticket_pdf(uid: &str, event_name: &str, venue_name: &str, event_date: &DateTime<Utc>) -> Vec<u8> {
    let qrcode = QRBuilder::new(uid)
    .build()
    .unwrap();

    let dimensions = 600;
    let mut img = ImageBuilder::default()
        .shape(Shape::Square)
        .fit_width(dimensions as u32)
        .to_pixmap(&qrcode)
        .encode_png().unwrap();

    /* PDF DOCUMENT MANIPULATION */

    let mut writer = PdfWriter::new();

    // Define reference ids
    let catalog_id = Ref::new(1);
    let page_tree_id = Ref::new(2);
    let page_id = Ref::new(3);
    let image_id = Ref::new(4);
    let s_mask_id = Ref::new(5);
    let content_id = Ref::new(6);
    let image_name = Name(b"Qr1");

    // Set up the page tree
    writer.catalog(catalog_id).pages(page_tree_id);
    writer.pages(page_tree_id).kids([page_id]).count(1);

    // Create a4 page
    let mut page = writer.page(page_id);
    let a4 = Rect::new(0.0, 0.0, 595.0, 842.0);
    page.media_box(a4);
    page.parent(page_tree_id);
    page.contents(content_id);
    page.resources().x_objects().pair(image_name, image_id);
    page.finish();

    // Load image from memory
    let dynamic = image::load_from_memory(&img).unwrap();

    // Process image
    let (filter, encoded, mask) = {
        let level = CompressionLevel::DefaultLevel as u8;
        let encoded = compress_to_vec_zlib(dynamic.to_rgb8().as_raw(), level);

        let mask = dynamic.color().has_alpha().then(|| {
            let alphas: Vec<_> = dynamic.pixels().map(|p| (p.2).0[3]).collect();
            compress_to_vec_zlib(&alphas, level)
        });

        (Filter::FlateDecode, encoded, mask)
    };

    let mut image = writer.image_xobject(image_id, &encoded);
    image.filter(filter);
    image.width(dynamic.width() as i32);
    image.height(dynamic.height() as i32);
    image.color_space().device_rgb();
    image.bits_per_component(8);
    if mask.is_some() {
        image.s_mask(s_mask_id);
    }
    image.finish();

    if let Some(encoded) = &mask {
        let mut s_mask = writer.image_xobject(s_mask_id, &encoded);
        s_mask.filter(filter);
        s_mask.width(dynamic.width() as i32);
        s_mask.height(dynamic.height() as i32);
        s_mask.color_space().device_gray();
        s_mask.bits_per_component(8);
    }

    // Size the image at 1pt per pixel.
    let w = dynamic.width() as f32;
    let h = dynamic.height() as f32;

    // Center the image on the page.
    let x = (a4.x2 - w) / 2.0;
    let y = ((a4.y2 - h) / 2.0)+50.0; 

    // [scale_x, skew_x, skew_y, scale_y, translate_x, translate_y]
    // PDF coordinate system starts at bottom left
    let mut content = Content::new();
    content.save_state();
    content.transform([w, 0.0, 0.0, h, x, y]);
    content.x_object(image_name);
    content.restore_state();

    content.begin_text();
    content.set_font(Name(b"Helvetica"), 14.0);
    content.next_line(a4.x2/2.0 - 15.0, a4.y2-50.0); //figure out way to center
    content.show(Str(b"Tikifi"));
    content.end_text();

    content.begin_text();
    content.next_line(50.0, a4.y2-700.0); //figure out way to center
    content.show(Str(format!("Event: {}", event_name).as_bytes()));
    content.end_text();

    content.begin_text();
    content.next_line(50.0, a4.y2-720.0); //figure out way to center
    content.show(Str(format!("Venue: {}", venue_name).as_bytes()));
    content.end_text();

    content.begin_text();
    content.next_line(50.0, a4.y2-740.0); //figure out way to center
    content.show(Str(format!("Date: {}", event_date).as_bytes()));
    content.end_text();

    writer.stream(content_id, &content.finish());

    writer.finish()

}

#[derive(Responder)]
#[response(status = 200, content_type = "pdf")]
struct PdfResponder(Vec<u8>);

#[get("/ticket/buy")]
async fn create_ticket(mut conn: Connection<Logs>, user: UserInfo) -> Result<Redirect, ApiError> {
    let cart = CartItem::get_info(&mut *conn, user.id.clone()).await?;
    for(item) in cart {
        Ticket::create(&mut *conn, item.event.uid, user.id.clone()).await?;
    }
    CartItem::clear_cart(&mut *conn, user.id.clone()).await?;
    Ok(Redirect::to("/dashboard/tickets"))
}

#[get("/ticket/<ticket_id>")]
async fn view_ticket(mut conn: Connection<Logs>, user: UserInfo, ticket_id: String) -> Result<PdfResponder, ApiError> {
    //std::fs::write("image.pdf", writer.finish());
    let ticket_info = Ticket::get_info(&mut *conn, ticket_id.clone(), user.id).await?;
    Ok(PdfResponder(generate_ticket_pdf(&ticket_id, &ticket_info.event_name, &ticket_info.venue_name, &ticket_info.event_date).await))
}

#[get("/ticket/check/<event_id>/<ticket_id>")]
async fn check_ticket(mut conn: Connection<Logs>, user: UserInfo, event_id: String, ticket_id: String) -> Result<String, ApiError> {
    let permitted = Ticket::check_ticket(&mut *conn, ticket_id.clone(), user.id, event_id).await?;
    Ok(permitted.to_string())
}

#[get("/reader")]
async fn ticket_reader(mut conn: Connection<Logs>, user: UserInfo, cur_uri: &rocket::http::uri::Origin<'_>) -> Result<Template, ApiError> {
    let mut ctx = Context::new();
    ctx.insert("path", &cur_uri.path().as_str());
    ctx.insert("user", &user);
    //ctx.insert("path", &cur_uri.path().as_str());

    let mut venue_dropdown_criteria = VenueFilterCriteria::new();
    venue_dropdown_criteria.owner = Some(user.id.clone());
    let venue_names: Option<Vec<ListingName>> = venue_dropdown_criteria.get_names(&mut *conn).await.ok(); 

    let mut event_dropdown_criteria = EventFilterCriteria::new();
    event_dropdown_criteria.author = Some(user.id.clone());
    let event_names: Option<Vec<ListingName>> = event_dropdown_criteria.get_names(&mut *conn).await.ok(); 

    match venue_names {
        Some(e) => {
            ctx.insert("venue_names", &e);
        }
        None => {
            ctx.insert("venue_names", &false);
        }
    }

    match event_names {
        Some(e) => {
            ctx.insert("event_names", &e);
        }
        None => {
            ctx.insert("event_names", &false);
        }
    }

    Ok(Template::render("reader", ctx.into_json()))
}

#[get("/like/<listing_id>")]
async fn like_listing(mut conn: Connection<Logs>, user: UserInfo, listing_id: String) -> Result<(), ApiError> {
    Like::add(&mut *conn, listing_id, user).await
}

#[get("/unlike/<listing_id>")]
async fn unlike_listing(mut conn: Connection<Logs>, user: UserInfo, listing_id: String) -> Result<(), ApiError> {
    Like::remove(&mut *conn, listing_id, user).await
}

#[derive(FromForm, Serialize, Debug)]
#[serde(crate = "rocket::serde")]
struct CartSubmission {
    event: String,
    amount: i64,
}

#[derive(Serialize, Debug)]
#[serde(crate = "rocket::serde")]
struct CartItem {
    event: Event,
    amount: i64,
}

impl CartItem {
    async fn get_info(mut conn: &mut PoolConnection<Postgres>, user_id: String) -> Result<Vec<CartItem>, ApiError> {
        let cart: Vec<CartItem> = sqlx::query("
        SELECT ev.uid, ev.name, ev.description, ev.event_date, ev.price, ev.thumbnail_url, ev.venue AS venue_id, ven.name AS venue_name, ct.event, ct.amount FROM cart AS ct 
        JOIN events AS ev ON ct.event = ev.uid 
        JOIN venues AS ven ON ev.venue = ven.uid
        WHERE ct.user = $1
        ")
        .bind(&user_id)
        .map(|row: PgRow| CartItem {
            event: Event {
                uid: row.get("uid"),
                name: row.get("name"),
                description: row.get("description"),
                event_date: row.get("event_date"),
                venue_id: row.get("venue_id"),
                venue_name: row.get("venue_name"),
                thumbnail_url: row.get("thumbnail_url"),
                price: row.get("price"),
            },
            amount: row.get("amount"),
        })
        .fetch_all(&mut *conn).await?;
        Ok(cart)
    }
    async fn clear_cart(mut conn: &mut PoolConnection<Postgres>, user_id: String) -> Result<(), ApiError> {
        sqlx::query("
        DELETE FROM public.cart WHERE \"user\"=$1;")
        .bind(&user_id)
        .execute(&mut *conn).await?;
        Ok(())
    }
}

#[post("/cart/add", data = "<data>")]
async fn add_to_cart(mut data: rocket::form::Form<CartSubmission>, mut conn: Connection<Logs>, user: UserInfo) -> Result<Redirect, ApiError> {
    
    sqlx::query("INSERT INTO public.cart(
        event, amount, \"user\")
        VALUES ($1, $2, $3)
        ON CONFLICT
        ON CONSTRAINT cart_pkey
        DO UPDATE SET amount = $4")
    .bind(&data.event)
    .bind(&data.amount)
    .bind(&user.id)
    .bind(&data.amount)
    .execute(&mut *conn).await?;

    Ok(Redirect::to("/"))

}

#[post("/cart/delete", data = "<data>")]
async fn delete_from_cart(mut data: rocket::form::Form<CartSubmission>, mut conn: Connection<Logs>, user: UserInfo) -> Result<Redirect, ApiError> {
    
    sqlx::query("
    DELETE FROM public.cart WHERE event=$1 AND user=$2;")
    .bind(&data.event)
    .bind(&user.id)
    .execute(&mut *conn).await?;

    Ok(Redirect::to("/"))

}

#[get("/cart/view")]
async fn view_cart(mut conn: Connection<Logs>, user: UserInfo, cur_uri: &rocket::http::uri::Origin<'_>) -> Result<Template, ApiError> {
    
    let mut ctx = Context::new();
    ctx.insert("path", &cur_uri.path().as_str());

    ctx.insert("user", &user);
    
    let cart = CartItem::get_info(&mut *conn, user.id).await?;

    ctx.insert("cart", &cart);

    Ok(Template::render("cart", ctx.into_json()))

}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .attach(Logs::init())
        .mount("/", routes![ticket_reader, delete_from_cart, view_cart, add_to_cart, dashboard_tickets, /*like_listing, unlike_listing,*/ create_ticket, view_ticket, google_callback, google_login, google_logout, index, dashboard_venues, dashboard_events, get_venue, get_event, get_event_mini_listing, search_listings, edit_venue, delete_venue, delete_event, add_event, edit_event, add_listing, dashboard, check_ticket])
        .mount("/assets", FileServer::from("./assets"))
        .mount("/images", FileServer::from("./images"))
        .register("/", catchers![default_catcher, forbidden_catcher])
        .attach(OAuth2::<Google>::fairing("google"))
        .attach(Template::fairing())
}