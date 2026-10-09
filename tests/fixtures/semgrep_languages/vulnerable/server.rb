class UsersController
  def lookup
    User.where("name = '#{params[:name]}'")
    system("ls #{params[:path]}")
    Marshal.load(params[:data])
    params.permit!
  end

  skip_before_action :verify_authenticity_token
end
