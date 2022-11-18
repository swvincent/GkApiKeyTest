#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["GkApiKeyTest/GkApiKeyTest.csproj", "GkApiKeyTest/"]
RUN dotnet restore "GkApiKeyTest/GkApiKeyTest.csproj"
COPY . .
WORKDIR "/src/GkApiKeyTest"
RUN dotnet build "GkApiKeyTest.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "GkApiKeyTest.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "GkApiKeyTest.dll"]