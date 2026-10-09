class UsersController
  def lookup
    User.where(name: params[:name])
    system("printf", "%s", params[:name])
    YAML.safe_load(params[:data])
    params.permit(:name)
  end
end
