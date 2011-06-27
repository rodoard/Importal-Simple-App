require 'rubygems'
require 'bundler'
Bundler.require
require 'sinatra'
require 'digest/sha1'
require 'dm-core'
require 'dm-migrations'
require 'dm-validations'

# Open the database
DataMapper.setup(:default, ENV['DATABASE_URL'] || "sqlite3://#{Dir.pwd}/db/development.db")

#Models
class User  
  include DataMapper::Resource  
  
  has n, :roles , :through => Resource
  property :id,           Serial
  property :salt, String
  property :email, String,:unique=>true,:format => :email_address ,:required=>true
  property :encrypted_password, String,:required=>true

  def self.random_string(len)  
   chars = ('a'..'z').to_a + ('A'..'Z').to_a
   (0...len).collect { chars[Kernel.rand(chars.length)] }.join
  end
  
  def self.encrypt(pass,salt)
      Digest::SHA1.hexdigest(pass+salt)
  end 
  
  def uroles 
      self.roles.collect {|r|r.name}.join(',')
  end   
  
  def password=(password)
   @password = password
   self.salt = User.random_string(10) unless self.salt
   self.encrypted_password=User.encrypt(@password, self.salt)
  end 
  def valid_password?(password) self.salt
   self.encrypted_password==User.encrypt(password, self.salt)
  end 
  
  def self.can_add_new?
     count < 3
  end 
  
end

class Role 
  include DataMapper::Resource  
  
  has n, :users, :through => Resource
  property :id,           Serial
  property :name, String,:unique=>true,:required=>true
  
  def self.roles(ids)
     all(:conditions=>["id in (#{ids.join(',')})"])
  end 
  
  def self.can_add_new?
     count < 3
  end 
  
end 

DataMapper.auto_upgrade!

enable :sessions

#Routing
get '/' do
 @users=User.all || []
 @roles=Role.all 
 erb :index
end  

get '/user/new' do
  if User.can_add_new? 
    @roles=Role.all || []  
    erb :"user/new"
  else 
    erb "User limit reached."
  end   
end

post '/user/create' do   
  user = User.new(
         :email => params[:email],
         :password=>params[:password]
    )
    
  Role.roles(params[:roles]).each do |r|
   user.roles << r
  end
  if user.save && User.can_add_new?
     status 201
     redirect '/user/'+user.id.to_s  
  else
    status 412
    redirect '/'   
  end
end

get '/user/:id' do
  @user = User.get(params[:id])
  unless @user
   redirect '/'
  else
    erb :"user/show"
  end  
end 

get '/user/:id/edit' do
  @user = User.get(params[:id])
  unless @user
   redirect '/'
  else
    erb :"user/edit"
  end  
end 

post '/user/:id/password_check' do
  @user = User.get(params[:id])
  if @user.valid_password?(params[:password])
    session[:message]="Password matches."
  else 
    session[:message]="Password does not match."
  end 
  redirect '/user/'+@user.id.to_s
end 

get '/user/:id/delete' do
  @user = User.get(params[:id])
  unless @user
   redirect '/'
  else
    erb :"user/delete_confirm"
  end  
end 

put '/user/:id' do
  @user = User.get(params[:id])
  @user.password=params[:password]
  if @user.save
    status 201
    session[:message]="Password updated successfully."
    redirect '/user/'+@user.id.to_s
  else
    status 412
    redirect '/'   
  end
end

delete '/user/:id' do
  user=User.get(params[:id])
  user.destroy if user 
  redirect '/'  
end

get '/role/new' do
  if Role.can_add_new?
    erb :"role/new"
  else 
   erb "Role limit reached."  
  end
end

post '/role/create' do   
  role = Role.new(
         :name => params[:name]
  )
  if role.save && Role.can_add_new?
    status 201
    redirect '/role/'+role.id.to_s  
  else
    status 412
    redirect '/'   
  end
end

get '/role/:id' do
  @role = Role.get(params[:id])
  unless @role
   redirect '/'
  else
    erb :"role/show"
  end  
end 

get '/roles' do
  @roles = Role.all
  erb :"role/index"
end 

get '/role/:id/delete' do
  @role = Role.get(params[:id])
  unless @role
   redirect '/'
  else
    erb :"role/delete_confirm"
  end  
end

delete '/role/:id' do
  role=Role.get(params[:id])
  role.destroy if role 
  redirect '/roles'  
end
