using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

namespace Candlewire.Identity.Server.Migrations.PersistenceDb
{
    public partial class InitialCreate : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "PersistenceItems",
                columns: table => new
                {
                    PersistenceId = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    PersistenceToken = table.Column<string>(type: "text", nullable: true),
                    PersistenceKey = table.Column<string>(type: "text", nullable: true),
                    PersistenceData = table.Column<string>(type: "text", nullable: true),
                    PersistenceExpiration = table.Column<DateTime>(type: "timestamp without time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PersistenceItems", x => x.PersistenceId);
                });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "PersistenceItems");
        }
    }
}
