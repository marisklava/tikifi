#[macro_use] extern crate rocket;
extern crate chrono;

use rocket::{post, response::content, routes, form::{self, Form}, serde::{Deserialize, Serialize, json::*}};
use rocket::http::{Cookie, CookieJar, SameSite, ContentType};
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

use uuid::Uuid; 

#[derive(Database)]
#[database("tikifi")]
struct Logs(sqlx::PgPool);

#[derive(FromForm)]
pub struct EventSubmission<'r> {
    name: String,
    description: String,
    event_date: String,
    //is_draft: bool,
    venue: i64,
    #[field(validate = validate_image())]
    thumbnail: rocket::fs::TempFile<'r>,
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
    author: Option<String>,
    text: Option<String>,
    venue_name: Option<String>, //UNIMPLEMENTED
    event_date: Option<DateTime<Utc>>,
    venue_id: Option<i64>,
    is_draft: bool, //UNIMPLEMENTED
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
        if(self.text.is_some()) { q.push(" AND lower(ev.name) LIKE '%' || "); q.push_bind(self.text.unwrap().to_lowercase()); q.push(" || '%'");};
        if(self.author.is_some()) { q.push(" AND ev.author = "); q.push_bind(self.author.unwrap());};
        if(self.limit.is_some()) { q.push(" LIMIT "); q.push_bind(self.limit.unwrap());};

        q.build().map(|row: PgRow| Event {
            uid: row.get("uid"),
            name: row.get("name"),
            description: row.get("description"),
            event_date: row.get("event_date"),
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
pub struct VenueSubmission<'r> {
    name: String,
    description: String,
    //capacity: i64,
    address: String,
    //thumbnail_url: String,
    #[field(validate = validate_image())] //ContentType::new("image", "*")
    thumbnail: rocket::fs::TempFile<'r>,
}

//thumbnail: rocket::fs::TempFile<'r>,
fn validate_image<'v>(file: &rocket::fs::TempFile<'_>) -> form::Result<'v, ()> {
    let ctt = file.content_type().unwrap();
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
    uid: Option<i64>,
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
    async fn exec_query(self, mut conn: &mut PoolConnection<Postgres>) -> Result<Vec<Venue>, rocket_db_pools::sqlx::Error> {
        fn sep(c: i32) -> String {
            if(c==1) { return " WHERE ".to_string() }
            else { return " AND ".to_string() }
        }

        let mut q = QueryBuilder::new("SELECT ven.uid, ven.name, ven.description, ven.capacity, ven.address, ven.thumbnail_url FROM venues AS ven WHERE true");
        
        if(self.uid.is_some()) { q.push(" AND uid = "); q.push_bind(self.uid.unwrap());};
        if(self.owner.is_some()) { q.push(" AND owner = "); q.push_bind(self.owner.unwrap());};
        if(self.text.is_some()) { q.push(" AND ven.name LIKE %"); q.push_bind(self.text.unwrap()); q.push("%");};

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

#[post("/events", data = "<data>")]
async fn add_event(mut data: rocket::form::Form<EventSubmission<'_>>, mut conn: Connection<Logs>, cookies: &CookieJar<'_>) -> Option<Redirect> {
    match get_current_user(cookies).await {
        Some(c) => {
            let thumb_dir = format!("images/{}", &Uuid::new_v4().to_string());
            data.thumbnail.persist_to(&thumb_dir).await.unwrap(); //todo: upload to cdn
            let a = sqlx::query("INSERT INTO public.events(
                name, description, event_date, venue, author, thumbnail_url)
                VALUES ($1, $2, $3, $4, $5, $6)")
            .bind(&data.name)
            .bind(&data.description)
            .bind(&data.event_date)
            .bind(&data.venue)
            .bind(&c.id)
            .bind(&format!("/{}",&thumb_dir))
            .execute(&mut *conn).await.ok()?;
            Some(Redirect::to("/dashboard/venues"))
        },
        None => None
    }
}

#[post("/venues", data = "<data>")]
async fn add_venue(mut data: rocket::form::Form<VenueSubmission<'_>>, mut conn: Connection<Logs>, cookies: &CookieJar<'_>) -> Option<Redirect> {
    match get_current_user(cookies).await {
        Some(c) => {
            let thumb_dir = format!("images/{}", &Uuid::new_v4().to_string());
            data.thumbnail.persist_to(&thumb_dir).await.unwrap(); //todo: upload to cdn
            let a = sqlx::query("INSERT INTO public.venues(
                name, description, capacity, address, thumbnail_url, owner)
                VALUES ($1, $2, $3, $4, $5, $6)")
            .bind(&data.name)
            .bind(&data.description)
            .bind(&500)
            .bind(&data.address)
            .bind(&format!("/{}",&thumb_dir))
            .bind(&c.id)
            .execute(&mut *conn).await.ok()?;
            Some(Redirect::to("/dashboard/venues"))
        },
        None => None
    }
}

#[post("/venues/<id>", data = "<data>")]
async fn edit_venue(mut data: rocket::form::Form<VenueSubmission<'_>>, id: i64, mut conn: Connection<Logs>, cookies: &CookieJar<'_>) -> Option<Redirect> {
    let thumb_dir = format!("images/{}", &Uuid::new_v4().to_string());
    data.thumbnail.persist_to(&thumb_dir).await.unwrap(); //todo: upload to cdn
    match get_current_user(cookies).await {
        Some(c) => {
            let a = sqlx::query("UPDATE venues SET name=$1, description=$2, capacity=$3, address=$4, thumbnail_url=$5 WHERE uid=$6 AND owner=$7")
            .bind(&data.name)
            .bind(&data.description)
            .bind(&500)
            .bind(&data.address)
            .bind(&format!("/{}",&thumb_dir))
            .bind(id)
            .bind(&c.id)
            .execute(&mut *conn).await.ok()?;
            Some(Redirect::to("/dashboard/venues"))
        },
        None => None
    }
}

#[get("/venues/<id>/delete")]
async fn delete_venue( id: i64, mut conn: Connection<Logs>, cookies: &CookieJar<'_>) -> Option<Redirect> {
    match get_current_user(cookies).await {
        Some(c) => {
            let a = sqlx::query("DELETE FROM venues WHERE uid=$1 AND owner=$2")
            .bind(id)
            .bind(&c.id)
            .execute(&mut *conn).await.ok()?;
            Some(Redirect::to("/dashboard/venues"))
        },
        None => None
    }
}

async fn get_featured_events(mut conn: &mut PoolConnection<Postgres>, limit: i32) -> Option<Vec<Event>> {
    let mut criteria = EventFilterCriteria::new();
    criteria.limit = Some(limit); 
    criteria.exec_query(&mut *conn).await.ok()
}

async fn render_listings(events: Vec<Event>) -> Option<Template> {
    let mut ctx = Context::new();
    ctx.insert("events", &events);
    Some(Template::render("results", ctx.into_json()))
}

#[get("/search?<query>")]
async fn search_listings(mut conn: Connection<Logs>, query: String, cookies: &CookieJar<'_>) -> Option<Template> {
    let mut ctx = Context::new();

    match get_current_user(cookies).await {
        Some(c) => ctx.insert("user", &c),
        None => ctx.insert("user", &false),
    };
    
    let mut criteria = EventFilterCriteria::new();
    criteria.text = Some(query); 
    let events = criteria.exec_query(&mut *conn).await.ok()?;
    if(events.len() == 0) { return None }
    render_listings(events).await
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

    Some(Template::render("dashboard_listings", ctx.into_json()))
}

#[get("/dashboard/events")]
async fn dashboard_events(mut conn: Connection<Logs>, cookies: &CookieJar<'_>) -> Option<Template> {
    let mut ctx = Context::new();
    let mut criteria = EventFilterCriteria::new();

    match get_current_user(cookies).await {
        Some(c) => {
            ctx.insert("user", &c);
            criteria.author = Some(c.id.clone());
        },
        None => {Redirect::to("/");},
    };
    print!("{:?}", criteria);

    let events = criteria.exec_query(&mut *conn).await.ok(); 

    match events {
        Some(e) => {
            ctx.insert("events", &e);
        }
        None => {
            ctx.insert("events", &false);
        }
    }

    Some(Template::render("dashboard_listings", ctx.into_json()))
}

use fast_qr::convert::ConvertError;
use fast_qr::convert::{image::ImageBuilder, Builder, Shape};
use fast_qr::qr::QRBuilder;
use std::io::Read;
use std::io::Cursor;
use std::io::BufWriter;

use image::{ColorType, GenericImageView, ImageFormat};
use miniz_oxide::deflate::{compress_to_vec_zlib, CompressionLevel};
use pdf_writer::{Content, Filter, Finish, Name, PdfWriter, Rect, Ref, Str};

#[get("/sample_ticket")]
async fn sample_ticket(mut conn: Connection<Logs>, cookies: &CookieJar<'_>) -> Option<String> {
    let qrtext = "required_qr";

    //let default_font = fonts::from_files(".\\fonts\\WorkSans", "WorkSans", None)
    //let image = elements::Image::from_path(".\\assets\\logo.jpg")

    let qrcode = QRBuilder::new(qrtext)
        .build()
        .unwrap();

    let dimensions = 600;
    let mut img_rgb: Vec<u8> = Vec::new();
    let mut img_rgb_out: Vec<u8> = vec![0u8; dimensions * dimensions * 3];
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
    let y = (a4.y2 - h) / 2.0; 
 
    // [scale_x, skew_x, skew_y, scale_y, translate_x, translate_y]
    // PDF coordinate system starts at bottom left
    let mut content = Content::new();
    content.save_state();
    content.transform([w, 0.0, 0.0, h, x, y]);
    content.x_object(image_name);
    content.restore_state();
    content.begin_text();
    content.set_font(Name(b"Helvetica"), 14.0);
    content.next_line(a4.x2/2.0 - 50.0, a4.y2-50.0); //figure out way to center
    content.show(Str(b"Hello World from Rust!"));
    content.end_text();
    writer.stream(content_id, &content.finish());

    // Write the thing to a file.
    std::fs::write("image.pdf", writer.finish());

    Some("yes".to_string())
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .attach(Logs::init())
        .mount("/", routes![sample_ticket, google_callback, google_login, index, dashboard_venues, dashboard_events, get_venue, get_event, search_listings, edit_venue, delete_venue, /*add_event,*/ add_venue, dashboard])
        .mount("/assets", FileServer::from("./assets"))
        .mount("/images", FileServer::from("./images"))
        .attach(OAuth2::<Google>::fairing("google"))
        .attach(Template::fairing())
}